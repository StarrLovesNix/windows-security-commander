"""
connection_monitor.py - Real-time TCP/UDP connection tracking.

Polls psutil.net_connections() every second to detect:
  - New established outbound/inbound connections (mapped to process name)
  - New listening ports (baseline deviation)
  - Connections to suspicious ports (known malware/C2 ports)

Emits: CONN_NEW, CONN_LISTEN events.
"""

import logging
import socket
import threading
from datetime import datetime
from typing import Dict, Optional, Set, Tuple

import psutil

from .events import EventType, SecurityEvent, Severity, event_queue

logger = logging.getLogger(__name__)

# Ports strongly associated with backdoors, C2, and attack tools.
SUSPICIOUS_PORTS = {
    4444, 4445, 4446, 4447,   # Metasploit default
    1337, 31337,               # Elite/leet ports, common in old malware
    9999, 6666, 6667, 6668, 6669,  # IRC (often used for botnet C2)
    1080, 3128, 8888,          # Proxy ports abused by malware
    5554, 9996,                # Sasser worm ports
    12345, 27374,              # NetBus, SubSeven
    65535,                     # Common backdoor port
}

# Well-known legitimate service ports — new listeners on these are expected.
KNOWN_LISTEN_PORTS = {
    80, 443, 8080, 8443,       # HTTP/HTTPS
    53,                        # DNS
    22, 3389,                  # SSH, RDP
    25, 587, 465, 993, 995,    # Mail
    445, 139, 137, 138,        # SMB/NetBIOS
    135,                       # RPC
    5040, 5357,                # Windows services
    1900,                      # SSDP/UPnP
    5353,                      # mDNS
}


def _process_name(pid: Optional[int]) -> str:
    if pid is None:
        return "unknown"
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return f"pid:{pid}"


def _resolve(ip: str) -> str:
    """Reverse-resolve an IP to hostname, falling back to the IP itself."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip


def _conn_key(conn) -> Tuple:
    return (conn.pid, conn.laddr, conn.raddr, conn.status)


class ConnectionMonitor:
    def __init__(self, config: dict, poll_interval: float = 1.0):
        self.poll_interval = poll_interval
        self._prev: Dict[Tuple, object] = {}
        self._prev_listening: Set[Tuple] = set()
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="ConnectionMonitor"
        )

    def start(self):
        logger.info("Starting ConnectionMonitor")
        self._seed()
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=5)

    # ------------------------------------------------------------------

    def _seed(self):
        """Snapshot current connections without emitting events."""
        try:
            for c in psutil.net_connections(kind="inet"):
                self._prev[_conn_key(c)] = c
                if c.status == "LISTEN" and c.laddr:
                    self._prev_listening.add((c.laddr.port, c.pid))
        except psutil.AccessDenied:
            logger.warning(
                "AccessDenied reading connections — run as Administrator for full visibility"
            )

    def _run(self):
        while not self._stop.is_set():
            try:
                self._poll()
            except Exception as exc:
                logger.error("ConnectionMonitor poll error: %s", exc)
            self._stop.wait(self.poll_interval)

    def _poll(self):
        try:
            conns = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            return

        current: Dict[Tuple, object] = {}
        current_listening: Set[Tuple] = set()

        for c in conns:
            key = _conn_key(c)
            current[key] = c

            if c.status == "LISTEN" and c.laddr:
                current_listening.add((c.laddr.port, c.pid))

            # Emit for newly established connections only
            if key not in self._prev and c.status == "ESTABLISHED" and c.raddr:
                self._emit_connection(c)

        # New listening ports
        for port, pid in current_listening - self._prev_listening:
            self._emit_listen(port, pid)

        self._prev = current
        self._prev_listening = current_listening

    def _emit_connection(self, conn):
        proc = _process_name(conn.pid)
        remote_ip = conn.raddr.ip
        remote_port = conn.raddr.port
        local_port = conn.laddr.port if conn.laddr else 0

        severity = Severity.INFO
        flags = []

        if remote_port in SUSPICIOUS_PORTS:
            severity = Severity.HIGH
            flags.append(f"suspicious port {remote_port}")

        hostname = _resolve(remote_ip)
        display = hostname if hostname != remote_ip else remote_ip
        flag_str = f" [{', '.join(flags)}]" if flags else ""

        event_queue.put(SecurityEvent(
            timestamp=datetime.now(),
            event_type=EventType.CONN_NEW,
            severity=severity,
            source=proc,
            description=f"{proc} -> {display}:{remote_port}{flag_str}",
            details={
                "pid": conn.pid,
                "process": proc,
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "hostname": hostname,
                "proto": "tcp" if conn.type == 1 else "udp",
            },
        ))

    def _emit_listen(self, port: int, pid: Optional[int]):
        proc = _process_name(pid)
        severity = Severity.MEDIUM if port not in KNOWN_LISTEN_PORTS else Severity.INFO
        event_queue.put(SecurityEvent(
            timestamp=datetime.now(),
            event_type=EventType.CONN_LISTEN,
            severity=severity,
            source=proc,
            description=f"New listening port: {port} ({proc})",
            details={"port": port, "pid": pid, "process": proc},
        ))
