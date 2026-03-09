"""
dns_monitor.py - DNS query monitoring via Windows DNS client cache.

Polls the Windows DNS client cache (Get-DnsClientCache) every few seconds
and emits an event for each new entry. This gives per-domain visibility
without requiring packet capture.

Emits: DNS events.
"""

import json
import logging
import threading
from datetime import datetime
from typing import Set

from .events import EventType, SecurityEvent, Severity, event_queue
from .subprocess_utils import run_hidden

logger = logging.getLogger(__name__)

# Domain patterns that warrant elevated severity regardless of context.
SUSPICIOUS_PATTERNS = [
    ".onion",           # Tor hidden services leaking to DNS (shouldn't happen normally)
    "raw.githubusercontent.com",  # Common dropper staging
    "pastebin.com",     # Common dropper staging
    "ngrok.io",         # Tunneling service, often abused
    "serveo.net",       # Tunneling service
    "portmap.io",       # Tunneling service
]


class DNSMonitor:
    def __init__(self, config: dict, poll_interval: float = 5.0):
        self.poll_interval = poll_interval
        self._seen: Set[str] = set()
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="DNSMonitor"
        )

    def start(self):
        logger.info("Starting DNSMonitor")
        self._seed()
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=5)

    # ------------------------------------------------------------------

    def _get_cache(self) -> list:
        try:
            result = run_hidden(
                [
                    "powershell", "-NoProfile", "-NonInteractive", "-Command",
                    "Get-DnsClientCache | Select-Object Entry,RecordType,Data "
                    "| ConvertTo-Json -Compress",
                ],
                timeout=15,
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout.strip())
                # PowerShell returns a dict (not list) when there is only one entry
                return data if isinstance(data, list) else [data]
        except Exception as exc:
            logger.debug("DNS cache poll error: %s", exc)
        return []

    def _seed(self):
        self._seen = {e.get("Entry", "") for e in self._get_cache() if e.get("Entry")}

    def _run(self):
        while not self._stop.is_set():
            try:
                self._poll()
            except Exception as exc:
                logger.error("DNSMonitor error: %s", exc)
            self._stop.wait(self.poll_interval)

    def _poll(self):
        for entry in self._get_cache():
            name = entry.get("Entry", "")
            if not name or name in self._seen:
                continue
            self._seen.add(name)
            self._emit(name, entry.get("Data", ""), entry.get("RecordType", ""))

    def _emit(self, name: str, data: str, record_type: str):
        severity = Severity.INFO
        name_lower = name.lower()
        for pattern in SUSPICIOUS_PATTERNS:
            if pattern in name_lower:
                severity = Severity.HIGH
                break

        event_queue.put(SecurityEvent(
            timestamp=datetime.now(),
            event_type=EventType.DNS,
            severity=severity,
            source="dns-client",
            description=f"DNS: {name} -> {data}",
            details={"domain": name, "data": data, "record_type": record_type},
        ))
