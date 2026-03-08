"""
firewall_manager.py - Windows Firewall management via netsh.

Adds/removes both inbound and outbound block rules for individual IPs.
All rules are prefixed with "SecurityCommander-Block-" so they can be
listed and cleaned up easily.

All IP inputs are validated before use in any subprocess call to prevent
command injection.
"""

import logging
import re
import subprocess
from typing import List, Tuple

logger = logging.getLogger(__name__)

RULE_PREFIX = "SecurityCommander-Block-"


def _run(args: List[str], timeout: int = 15) -> Tuple[bool, str, str]:
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0, r.stdout.strip(), r.stderr.strip()
    except Exception as exc:
        return False, "", str(exc)


def _validate_ip(ip: str) -> str:
    """Strict IPv4 validation — raises ValueError on anything suspicious."""
    ip = str(ip).strip()
    if not re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ip):
        raise ValueError(f"Invalid IPv4 address: {ip!r}")
    if not all(0 <= int(o) <= 255 for o in ip.split(".")):
        raise ValueError(f"IPv4 octet out of range: {ip!r}")
    return ip


def is_ip_blocked(ip: str) -> bool:
    try:
        ip = _validate_ip(ip)
    except ValueError:
        return False
    rule_name = f"{RULE_PREFIX}{ip}-IN"
    ok, out, _ = _run(["netsh", "advfirewall", "firewall", "show", "rule",
                        f"name={rule_name}"])
    return ok and rule_name in out


def block_ip(ip: str) -> Tuple[bool, str]:
    """
    Add inbound + outbound block rules for the given IP.
    Returns (success, message).
    """
    try:
        ip = _validate_ip(ip)
    except ValueError as exc:
        return False, str(exc)

    if is_ip_blocked(ip):
        return True, f"{ip} already blocked"

    base = f"{RULE_PREFIX}{ip}"
    errors = []

    for direction in ("in", "out"):
        rule_name = f"{base}-{direction.upper()}"
        ok, _, err = _run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            f"dir={direction}",
            "action=block",
            f"remoteip={ip}",
            "enable=yes",
            "profile=any",
            "description=SecurityCommander auto-block",
        ])
        if not ok:
            errors.append(f"{direction}: {err}")

    if not errors:
        logger.warning("REMEDIATION: Blocked %s via Windows Firewall", ip)
        return True, f"Blocked {ip} (inbound + outbound)"

    return False, f"Firewall block failed — {'; '.join(errors)}"


def unblock_ip(ip: str) -> Tuple[bool, str]:
    """Remove block rules for the given IP."""
    try:
        ip = _validate_ip(ip)
    except ValueError as exc:
        return False, str(exc)

    base = f"{RULE_PREFIX}{ip}"
    any_ok = False
    for suffix in ("IN", "OUT"):
        ok, _, _ = _run(["netsh", "advfirewall", "firewall", "delete", "rule",
                          f"name={base}-{suffix}"])
        any_ok = any_ok or ok

    return any_ok, f"Unblocked {ip}" if any_ok else f"No rules found for {ip}"


def list_blocked_ips() -> List[str]:
    """Return all IPs currently blocked by SecurityCommander rules."""
    ok, out, _ = _run([
        "netsh", "advfirewall", "firewall", "show", "rule",
        f"name={RULE_PREFIX}*",
    ])
    ips: List[str] = []
    for line in out.splitlines():
        m = re.search(r"RemoteIP:\s+(\d{1,3}(?:\.\d{1,3}){3})", line)
        if m:
            ip = m.group(1)
            if ip not in ips:
                ips.append(ip)
    return ips
