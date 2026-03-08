"""
events.py - Central event model and shared queue for Security Commander.

All monitors produce SecurityEvent objects and push them to event_queue.
The main thread and UI consume from event_queue.
"""

import queue
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EventType(str, Enum):
    CONN_NEW = "CONN_NEW"           # New outbound/inbound connection established
    CONN_LISTEN = "CONN_LISTEN"     # New listening port opened
    DNS = "DNS"                     # DNS query observed
    PROC_NEW = "PROC_NEW"           # New process started
    PROC_SUSPICIOUS = "PROC_SUSPICIOUS"  # Suspicious process or spawn chain
    LOGIN_SUCCESS = "LOGIN_SUCCESS" # Successful logon
    LOGIN_FAIL = "LOGIN_FAIL"       # Failed logon attempt
    LOGIN_BRUTE = "LOGIN_BRUTE"     # Brute force threshold crossed
    SERVICE_NEW = "SERVICE_NEW"     # New Windows service installed
    TASK_NEW = "TASK_NEW"           # New scheduled task created
    AUDIT_CLEAR = "AUDIT_CLEAR"     # Security audit log cleared
    THREAT_IP = "THREAT_IP"         # Connection to known-malicious IP
    FIREWALL_BLOCK = "FIREWALL_BLOCK"  # Auto-blocked by remediator
    PROCESS_KILL = "PROCESS_KILL"   # Process killed by remediator
    BASELINE_DEV = "BASELINE_DEV"   # Deviation from security baseline
    ARP_SPOOF = "ARP_SPOOF"         # ARP spoofing detected
    LAN_NEW = "LAN_NEW"             # New device on LAN
    POLICY_CHANGE = "POLICY_CHANGE" # Audit/security policy changed


@dataclass
class SecurityEvent:
    timestamp: datetime
    event_type: EventType
    severity: Severity
    source: str
    description: str
    details: Dict[str, Any] = field(default_factory=dict)
    remediated: bool = False
    acknowledged: bool = False

    def key(self) -> str:
        """Stable key for deduplication and alert cooldowns."""
        return f"{self.event_type.value}:{self.source}:{self.description[:80]}"


# Module-level singleton queue — every monitor pushes here, main thread consumes.
event_queue: queue.Queue = queue.Queue()
