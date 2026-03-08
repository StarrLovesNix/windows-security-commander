"""
threat_intel.py - IP reputation lookups via AbuseIPDB.

Checks outbound connection IPs against AbuseIPDB (free tier: 1000 checks/day).
Results are cached locally for 24 hours to avoid burning API quota.

Private/RFC1918 IPs are skipped automatically.

Usage:
    ti = ThreatIntel(config, data_dir)
    is_malicious, score, category = ti.check_ip("1.2.3.4")
"""

import ipaddress
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Tuple

logger = logging.getLogger(__name__)

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    logger.warning("requests not installed — threat intel lookups disabled. "
                   "Install with: pip install requests")

# IP ranges that are private/reserved and should never be checked externally.
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),  # Carrier-grade NAT
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return True   # Treat parse failures as private (skip lookup)


class ThreatIntel:
    CACHE_TTL = timedelta(hours=24)
    # AbuseIPDB confidence score threshold to call an IP malicious
    MALICIOUS_THRESHOLD = 50

    def __init__(self, config: dict, data_dir: Path):
        self._api_key: str = (
            config.get("threat_intel", {}).get("abuseipdb_api_key", "")
        )
        self._cache_path = data_dir / "threat_cache.json"
        self._cache: Dict[str, dict] = {}
        self._load_cache()

    # ------------------------------------------------------------------

    def check_ip(self, ip: str) -> Tuple[bool, int, str]:
        """
        Check an IP for malicious reputation.

        Returns:
            (is_malicious: bool, abuse_confidence_score: int, category: str)
        """
        if is_private(ip):
            return False, 0, "private"

        # Cache hit?
        cached = self._cache.get(ip)
        if cached:
            try:
                age = datetime.now() - datetime.fromisoformat(cached["checked_at"])
                if age < self.CACHE_TTL:
                    return cached["is_malicious"], cached["score"], cached["category"]
            except Exception:
                pass

        if not self._api_key:
            return False, 0, "no-api-key"

        if not HAS_REQUESTS:
            return False, 0, "requests-not-installed"

        return self._query_abuseipdb(ip)

    # ------------------------------------------------------------------

    def _query_abuseipdb(self, ip: str) -> Tuple[bool, int, str]:
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": self._api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 30},
                timeout=5,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                score: int = data.get("abuseConfidenceScore", 0)
                is_malicious = score >= self.MALICIOUS_THRESHOLD
                result = {
                    "is_malicious": is_malicious,
                    "score": score,
                    "category": "malicious" if is_malicious else "clean",
                    "checked_at": datetime.now().isoformat(),
                    "country": data.get("countryCode", ""),
                    "isp": data.get("isp", ""),
                    "domain": data.get("domain", ""),
                }
                self._cache[ip] = result
                self._save_cache()
                return is_malicious, score, result["category"]

            logger.debug("AbuseIPDB returned %d for %s", resp.status_code, ip)
        except Exception as exc:
            logger.debug("Threat intel API error for %s: %s", ip, exc)

        return False, 0, "api-error"

    def _load_cache(self):
        try:
            if self._cache_path.exists():
                self._cache = json.loads(self._cache_path.read_text())
        except Exception:
            self._cache = {}

    def _save_cache(self):
        try:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            self._cache_path.write_text(json.dumps(self._cache, indent=2))
        except Exception as exc:
            logger.debug("Threat cache save failed: %s", exc)
