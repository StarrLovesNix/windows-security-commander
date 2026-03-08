"""
event_log_monitor.py - Windows Event Log monitoring.

Reads Security, System, and Application event log channels for security-
relevant Event IDs. Detects brute-force login attacks by counting failed
logon events per source IP within a sliding time window.

Requires pywin32. Gracefully disabled if not installed.

Emits: LOGIN_SUCCESS, LOGIN_FAIL, LOGIN_BRUTE, PROC_NEW, SERVICE_NEW,
       TASK_NEW, AUDIT_CLEAR, POLICY_CHANGE events.
"""

import logging
import threading
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List

from .events import EventType, SecurityEvent, Severity, event_queue

logger = logging.getLogger(__name__)

try:
    import win32evtlog
    import pywintypes
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False
    logger.warning("pywin32 not installed — Windows Event Log monitoring disabled. "
                   "Install with: pip install pywin32")

# -----------------------------------------------------------------------
# Event ID registry
# (event_id) -> (type_tag, base_severity, description)
# -----------------------------------------------------------------------
EVENT_REGISTRY = {
    # Logon / authentication
    4624: (EventType.LOGIN_SUCCESS,  Severity.INFO,     "Successful logon"),
    4625: (EventType.LOGIN_FAIL,     Severity.LOW,      "Failed logon"),
    4648: (EventType.LOGIN_SUCCESS,  Severity.MEDIUM,   "Logon with explicit credentials"),
    4740: (EventType.LOGIN_BRUTE,    Severity.HIGH,     "Account locked out"),
    4771: (EventType.LOGIN_FAIL,     Severity.MEDIUM,   "Kerberos pre-auth failed"),
    4776: (EventType.LOGIN_FAIL,     Severity.LOW,      "NTLM credential validation"),
    # Privilege / policy
    4672: (EventType.POLICY_CHANGE,  Severity.LOW,      "Special privileges assigned at logon"),
    4673: (EventType.POLICY_CHANGE,  Severity.LOW,      "Privileged service called"),
    4719: (EventType.POLICY_CHANGE,  Severity.HIGH,     "System audit policy changed"),
    # User management
    4720: (EventType.SERVICE_NEW,    Severity.HIGH,     "User account created"),
    4722: (EventType.POLICY_CHANGE,  Severity.MEDIUM,   "User account enabled"),
    4725: (EventType.POLICY_CHANGE,  Severity.LOW,      "User account disabled"),
    4728: (EventType.POLICY_CHANGE,  Severity.MEDIUM,   "Member added to global security group"),
    4732: (EventType.POLICY_CHANGE,  Severity.MEDIUM,   "Member added to local security group"),
    4738: (EventType.POLICY_CHANGE,  Severity.MEDIUM,   "User account changed"),
    4756: (EventType.POLICY_CHANGE,  Severity.MEDIUM,   "Member added to universal group"),
    # Process
    4688: (EventType.PROC_NEW,       Severity.INFO,     "Process created"),
    # Scheduled tasks
    4698: (EventType.TASK_NEW,       Severity.MEDIUM,   "Scheduled task created"),
    4702: (EventType.TASK_NEW,       Severity.MEDIUM,   "Scheduled task updated"),
    # Audit
    1102: (EventType.AUDIT_CLEAR,    Severity.CRITICAL, "Security audit log cleared"),
    # Services
    7045: (EventType.SERVICE_NEW,    Severity.HIGH,     "New service installed"),
    7034: (EventType.SERVICE_NEW,    Severity.LOW,      "Service terminated unexpectedly"),
    # Firewall
    4946: (EventType.POLICY_CHANGE,  Severity.MEDIUM,   "Windows Firewall rule added"),
    4947: (EventType.POLICY_CHANGE,  Severity.MEDIUM,   "Windows Firewall rule modified"),
    4950: (EventType.POLICY_CHANGE,  Severity.MEDIUM,   "Windows Firewall rule deleted"),
}

LOGON_TYPES = {
    2: "Interactive", 3: "Network", 4: "Batch", 5: "Service",
    7: "Unlock", 8: "NetworkCleartext", 9: "NewCredentials",
    10: "RemoteInteractive", 11: "CachedInteractive",
}

CHANNELS = ["Security", "System", "Application"]


class EventLogMonitor:
    def __init__(self, config: dict, poll_interval: float = 3.0):
        self.poll_interval = poll_interval
        self._brute_threshold = (
            config.get("thresholds", {}).get("failed_login_brute", 5)
        )
        self._brute_window = (
            config.get("thresholds", {}).get("brute_window_seconds", 60)
        )
        self._failed: Dict[str, List[datetime]] = defaultdict(list)
        self._handles: Dict[str, object] = {}
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="EventLogMonitor"
        )

    def start(self):
        if not HAS_WIN32:
            return
        logger.info("Starting EventLogMonitor")
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=5)

    # ------------------------------------------------------------------

    def _open_handles(self):
        for channel in CHANNELS:
            try:
                handle = win32evtlog.OpenEventLog(None, channel)
                # Drain existing records so we only see new events going forward
                flags = (win32evtlog.EVENTLOG_BACKWARDS_READ |
                         win32evtlog.EVENTLOG_SEQUENTIAL_READ)
                win32evtlog.ReadEventLog(handle, flags, 0)
                self._handles[channel] = handle
            except Exception as exc:
                logger.warning("Cannot open event log '%s': %s", channel, exc)

    def _run(self):
        self._open_handles()
        while not self._stop.is_set():
            try:
                for channel, handle in self._handles.items():
                    self._poll_channel(channel, handle)
            except Exception as exc:
                logger.error("EventLogMonitor error: %s", exc)
            self._stop.wait(self.poll_interval)

    def _poll_channel(self, channel: str, handle):
        try:
            flags = (win32evtlog.EVENTLOG_FORWARDS_READ |
                     win32evtlog.EVENTLOG_SEQUENTIAL_READ)
            records = win32evtlog.ReadEventLog(handle, flags, 0)
            for rec in (records or []):
                eid = rec.EventID & 0xFFFF
                if eid in EVENT_REGISTRY:
                    self._dispatch(channel, rec, eid)
        except Exception as exc:
            logger.debug("Event log read (%s): %s", channel, exc)

    def _dispatch(self, channel: str, rec, eid: int):
        etype, base_sev, base_desc = EVENT_REGISTRY[eid]
        strings = list(rec.StringInserts or [])
        try:
            ts = datetime(*rec.TimeGenerated.timetuple()[:6])
        except Exception:
            ts = datetime.now()

        severity = base_sev
        desc = base_desc
        details = {"event_id": eid, "channel": channel}

        # -- Successful logon (4624) --
        if eid == 4624:
            username = strings[5] if len(strings) > 5 else "?"
            logon_type = int(strings[8]) if len(strings) > 8 and strings[8].isdigit() else 0
            src_ip = strings[18] if len(strings) > 18 else ""
            lt_name = LOGON_TYPES.get(logon_type, str(logon_type))
            desc = f"Logon: {username} ({lt_name})"
            if src_ip and src_ip not in ("-", ""):
                desc += f" from {src_ip}"
            if logon_type in (3, 10):
                severity = Severity.LOW  # network / remote logons get a bump
            details.update({"username": username, "logon_type": lt_name, "src_ip": src_ip})

        # -- Failed logon (4625) --
        elif eid == 4625:
            username = strings[5] if len(strings) > 5 else "?"
            logon_type = int(strings[10]) if len(strings) > 10 and strings[10].isdigit() else 0
            src_ip = strings[19] if len(strings) > 19 else ""
            lt_name = LOGON_TYPES.get(logon_type, str(logon_type))
            desc = f"Failed logon: {username} ({lt_name})"
            if src_ip and src_ip not in ("-", ""):
                desc += f" from {src_ip}"
            details.update({"username": username, "logon_type": lt_name, "src_ip": src_ip})
            if src_ip:
                self._track_brute(src_ip, ts)

        # -- Process created (4688) --
        elif eid == 4688:
            proc = strings[5] if len(strings) > 5 else strings[0] if strings else "?"
            parent = strings[13] if len(strings) > 13 else ""
            desc = f"Process created: {proc}"
            if parent:
                desc += f" <- {parent}"
            details.update({"process": proc, "parent": parent})
            # 4688 is very noisy at INFO level — skip unless interesting
            if severity == Severity.INFO:
                return

        # -- New service (7045) --
        elif eid == 7045:
            svc = strings[0] if strings else "?"
            path = strings[1] if len(strings) > 1 else ""
            desc = f"New service: {svc} ({path})"
            details.update({"service": svc, "path": path})

        # -- Scheduled task created/updated (4698/4702) --
        elif eid in (4698, 4702):
            task = strings[0] if strings else "?"
            desc = f"{'Created' if eid == 4698 else 'Updated'} scheduled task: {task}"
            details["task"] = task

        # -- Audit log cleared (1102) --
        elif eid == 1102:
            desc = "SECURITY AUDIT LOG CLEARED"

        # -- Account locked out (4740) --
        elif eid == 4740:
            username = strings[0] if strings else "?"
            desc = f"Account locked out: {username}"
            details["username"] = username

        # -- User account created (4720) --
        elif eid == 4720:
            username = strings[0] if strings else "?"
            desc = f"New user account created: {username}"
            details["username"] = username

        event_queue.put(SecurityEvent(
            timestamp=ts,
            event_type=etype,
            severity=severity,
            source=f"EventLog:{channel}",
            description=desc,
            details=details,
        ))

    def _track_brute(self, src_ip: str, ts: datetime):
        cutoff = ts - timedelta(seconds=self._brute_window)
        self._failed[src_ip] = [t for t in self._failed[src_ip] if t > cutoff]
        self._failed[src_ip].append(ts)
        count = len(self._failed[src_ip])
        # Emit exactly when threshold is first crossed (not on every subsequent hit)
        if count == self._brute_threshold:
            event_queue.put(SecurityEvent(
                timestamp=ts,
                event_type=EventType.LOGIN_BRUTE,
                severity=Severity.HIGH,
                source=src_ip,
                description=(
                    f"Brute force: {count} failed logins from {src_ip} "
                    f"in {self._brute_window}s"
                ),
                details={"src_ip": src_ip, "count": count,
                         "window_seconds": self._brute_window},
            ))
