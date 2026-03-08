"""
process_monitor.py - New process detection and suspicious spawn chain analysis.

Polls psutil process list every second to detect new PIDs. For each new
process it checks:
  - Is a known-suspicious tool name?
  - Was it spawned by an unusual parent (Office -> PowerShell, browser -> cmd)?
  - Does its command line contain obfuscation markers?

Emits: PROC_NEW, PROC_SUSPICIOUS events.
"""

import logging
import threading
from datetime import datetime
from typing import Dict, Optional, Set

import psutil

from .events import EventType, SecurityEvent, Severity, event_queue

logger = logging.getLogger(__name__)

# parent (lowercase) -> set of suspicious children (lowercase)
SUSPICIOUS_SPAWNS: Dict[str, Set[str]] = {
    # Office suite spawning shells / scripting engines
    "winword.exe":   {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
                      "mshta.exe", "rundll32.exe", "regsvr32.exe"},
    "excel.exe":     {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
                      "mshta.exe", "rundll32.exe"},
    "powerpnt.exe":  {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"},
    "onenote.exe":   {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"},
    "outlook.exe":   {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
                      "mshta.exe"},
    # PDF readers
    "acrobat.exe":   {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"},
    "acrord32.exe":  {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"},
    # Browsers (rare legitimate case — alert on it)
    "chrome.exe":    {"cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe"},
    "firefox.exe":   {"cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe"},
    "msedge.exe":    {"cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe"},
    "iexplore.exe":  {"cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe",
                      "rundll32.exe"},
    # WMI spawning interactive shells is a classic lateral movement technique
    "wmiprvse.exe":  {"cmd.exe", "powershell.exe"},
    # Installer spawning shells mid-install can indicate supply chain issues
    "msiexec.exe":   {"cmd.exe", "powershell.exe"},
}

# Process names that are suspicious regardless of parent
SUSPICIOUS_NAMES: Set[str] = {
    "mimikatz.exe",
    "procdump.exe",
    "pwdump.exe",
    "fgdump.exe",
    "wce.exe",          # Windows Credential Editor
    "mshta.exe",        # HTML Application Host — frequently abused
    "wscript.exe",      # Windows Script Host (flag for review)
    "cscript.exe",      # Windows Script Host (console)
}

# PowerShell obfuscation markers
PS_OBFUSCATION = {"-enc", "-encodedcommand", "-e ", "iex(", "invoke-expression"}


class ProcessMonitor:
    def __init__(self, config: dict, poll_interval: float = 1.0):
        self.poll_interval = poll_interval
        self._known_pids: Set[int] = set()
        self._pid_to_name: Dict[int, str] = {}
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="ProcessMonitor"
        )

    def start(self):
        logger.info("Starting ProcessMonitor")
        self._seed()
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=5)

    # ------------------------------------------------------------------

    def _seed(self):
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                self._known_pids.add(proc.pid)
                self._pid_to_name[proc.pid] = (proc.info["name"] or "").lower()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    def _run(self):
        while not self._stop.is_set():
            try:
                self._poll()
            except Exception as exc:
                logger.error("ProcessMonitor error: %s", exc)
            self._stop.wait(self.poll_interval)

    def _poll(self):
        current_pids: Set[int] = set()

        for proc in psutil.process_iter(["pid", "name", "exe", "ppid", "cmdline", "username"]):
            try:
                pid = proc.pid
                current_pids.add(pid)
                if pid not in self._known_pids:
                    name = (proc.info.get("name") or "").lower()
                    self._known_pids.add(pid)
                    self._pid_to_name[pid] = name
                    self._evaluate(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        # Prune stale PIDs
        gone = self._known_pids - current_pids
        for pid in gone:
            self._known_pids.discard(pid)
            self._pid_to_name.pop(pid, None)

    def _evaluate(self, proc):
        try:
            name = (proc.info.get("name") or "unknown").lower()
            exe = proc.info.get("exe") or ""
            ppid = proc.info.get("ppid")
            username = proc.info.get("username") or ""
            cmdline_parts = proc.info.get("cmdline") or []
            cmdline = " ".join(cmdline_parts)[:300].lower()
            parent_name = self._pid_to_name.get(ppid, "").lower() if ppid else ""

            severity = Severity.INFO
            flags = []

            # Suspicious spawn chain
            if parent_name in SUSPICIOUS_SPAWNS and name in SUSPICIOUS_SPAWNS[parent_name]:
                severity = Severity.HIGH
                flags.append(f"spawned by {parent_name}")

            # Inherently suspicious tool
            if name in SUSPICIOUS_NAMES:
                severity = Severity.CRITICAL
                flags.append("known offensive tool")

            # PowerShell encoded command / obfuscation
            if name in ("powershell.exe", "pwsh.exe"):
                for marker in PS_OBFUSCATION:
                    if marker in cmdline:
                        if severity.value < Severity.HIGH.value:
                            severity = Severity.HIGH
                        flags.append("encoded/obfuscated command")
                        break

            flag_str = f" [{', '.join(flags)}]" if flags else ""
            parent_str = f" <- {parent_name}" if parent_name else ""
            desc = f"New process: {name} (PID {proc.pid}){flag_str}{parent_str}"

            etype = (
                EventType.PROC_SUSPICIOUS
                if severity in (Severity.HIGH, Severity.CRITICAL)
                else EventType.PROC_NEW
            )

            # Skip noisy INFO-level process events to keep the feed readable
            if severity == Severity.INFO:
                return

            event_queue.put(SecurityEvent(
                timestamp=datetime.now(),
                event_type=etype,
                severity=severity,
                source=name,
                description=desc,
                details={
                    "pid": proc.pid,
                    "name": name,
                    "exe": exe,
                    "ppid": ppid,
                    "parent": parent_name,
                    "username": username,
                    "cmdline": cmdline[:200],
                    "flags": flags,
                },
            ))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
