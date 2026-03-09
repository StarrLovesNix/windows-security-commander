"""
network_scanner.py - LAN device discovery and ARP spoofing detection.

Reads the ARP table every 5 minutes (configurable) to:
  - Detect new devices joining the network
  - Detect ARP spoofing (same IP appearing with a different MAC)

Emits: LAN_NEW, ARP_SPOOF events.
"""

import logging
import re
import threading
from datetime import datetime
from typing import Dict

from .events import EventType, SecurityEvent, Severity, event_queue
from .subprocess_utils import run_hidden

logger = logging.getLogger(__name__)


def _read_arp_table() -> Dict[str, str]:
    """Return {ip: mac} parsed from `arp -a` output."""
    result: Dict[str, str] = {}
    try:
        out = run_hidden(
            ["arp", "-a"],
            timeout=10,
        )
        for line in out.stdout.splitlines():
            # Matches lines like:   192.168.1.1    aa-bb-cc-dd-ee-ff    dynamic
            m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([\da-f-]{17})", line.lower())
            if m:
                ip, mac = m.groups()
                # Skip broadcast / multicast MACs
                if mac not in ("ff-ff-ff-ff-ff-ff",):
                    result[ip] = mac
    except Exception as exc:
        logger.warning("ARP table read failed: %s", exc)
    return result


class NetworkScanner:
    def __init__(self, config: dict, scan_interval: float = 300.0):
        self.scan_interval = scan_interval
        self._known: Dict[str, str] = {}   # ip -> mac
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="NetworkScanner"
        )

    def start(self):
        logger.info("Starting NetworkScanner")
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=10)

    # ------------------------------------------------------------------

    def _run(self):
        self._seed()
        while not self._stop.is_set():
            try:
                self._scan()
            except Exception as exc:
                logger.error("NetworkScanner error: %s", exc)
            self._stop.wait(self.scan_interval)

    def _seed(self):
        self._known = _read_arp_table()
        logger.info("Network baseline: %d devices in ARP table", len(self._known))

    def _scan(self):
        current = _read_arp_table()

        for ip, mac in current.items():
            if ip not in self._known:
                # New device
                event_queue.put(SecurityEvent(
                    timestamp=datetime.now(),
                    event_type=EventType.LAN_NEW,
                    severity=Severity.LOW,
                    source="network-scanner",
                    description=f"New LAN device: {ip} ({mac})",
                    details={"ip": ip, "mac": mac},
                ))
            elif self._known[ip] != mac:
                # Same IP, different MAC — classic ARP spoofing indicator
                old_mac = self._known[ip]
                event_queue.put(SecurityEvent(
                    timestamp=datetime.now(),
                    event_type=EventType.ARP_SPOOF,
                    severity=Severity.CRITICAL,
                    source="network-scanner",
                    description=(
                        f"ARP SPOOFING DETECTED: {ip} "
                        f"MAC changed {old_mac} -> {mac}"
                    ),
                    details={"ip": ip, "old_mac": old_mac, "new_mac": mac},
                ))

        self._known.update(current)
