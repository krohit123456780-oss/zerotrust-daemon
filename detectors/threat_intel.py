"""
detectors/threat_intel.py

Checks IPs against real threat intelligence databases:
  - VirusTotal  (virus/malware IP reputation)
  - AbuseIPDB   (known malicious IPs)
  - Local blocklist (offline, no API needed)

Free tiers:
  - VirusTotal: 500 requests/day
  - AbuseIPDB : 1000 requests/day
"""

import time
import hashlib
import logging
import urllib.request
import urllib.parse
import json
import threading
from datetime import datetime, timedelta

logger = logging.getLogger("daemon")

# ── KNOWN MALICIOUS IP RANGES (offline, no API) ──
KNOWN_MALICIOUS_SUBNETS = [
    "0.0.0.0/8",
    "10.0.0.0/8",     # Private — not malicious but shouldn't appear as external src
    "100.64.0.0/10",
    "169.254.0.0/16", # Link-local — suspicious as a source
    "198.18.0.0/15",
    "240.0.0.0/4",
]

# Known bad ports used by common malware/RATs
MALWARE_PORT_SIGNATURES = {
    4444:  "Metasploit default port",
    1337:  "Common backdoor/C2 port",
    31337: "Elite/Back Orifice",
    12345: "NetBus RAT",
    23:    "Telnet (unencrypted, high risk)",
    5900:  "VNC (often exploited)",
    6667:  "IRC C2 bot communication",
    8545:  "Ethereum node (crypto miner)",
    3333:  "Crypto mining pool (Monero)",
    14444: "Crypto mining pool",
    45700: "Mirai botnet",
}

# DNS sinkholes and known C2 domains (small sample)
KNOWN_C2_DOMAINS = {
    "update.microsoft.com.evil.com",
    "windowsupdate.com.attacker.net",
}


class ThreatIntelChecker:
    def __init__(self, config):
        self.config = config
        self._cache: dict[str, dict] = {}       # IP -> result cache
        self._cache_ttl = timedelta(hours=6)
        self._lock = threading.Lock()
        self._request_count = 0
        self._daily_limit = 450  # stay under free tier

    def check_ip(self, ip: str) -> dict | None:
        """
        Check an IP against all available threat sources.
        Returns threat dict if malicious, None if clean.
        """
        # Check cache first
        cached = self._get_cache(ip)
        if cached is not None:
            return cached if cached.get("malicious") else None

        result = None

        # 1. Local blocklist checks (instant, no API)
        result = self._check_local(ip)
        if result:
            self._set_cache(ip, result)
            return result

        # 2. AbuseIPDB (best for network threats)
        if self.config.abuseipdb_key and self._request_count < self._daily_limit:
            result = self._check_abuseipdb(ip)
            if result:
                self._set_cache(ip, result)
                return result

        # 3. VirusTotal (best for malware-associated IPs)
        if self.config.virustotal_key and self._request_count < self._daily_limit:
            result = self._check_virustotal(ip)
            if result:
                self._set_cache(ip, result)
                return result

        # Clean — cache negative result
        self._set_cache(ip, {"malicious": False})
        return None

    def check_ports(self, open_ports: list[int]) -> dict | None:
        """Check if any open ports match known malware signatures."""
        for port in open_ports:
            if port in MALWARE_PORT_SIGNATURES:
                return {
                    "malicious": True,
                    "source": "port-signature",
                    "reason": f"Port {port} — {MALWARE_PORT_SIGNATURES[port]}",
                    "score": 85,
                }
        return None

    # ── LOCAL CHECKS (no API key needed) ──────
    def _check_local(self, ip: str) -> dict | None:
        """Fast local checks — runs instantly without network calls."""
        import ipaddress
        try:
            addr = ipaddress.ip_address(ip)

            # Loopback is fine
            if addr.is_loopback:
                return None

            # Multicast — suspicious on a device ARP
            if addr.is_multicast:
                return {"malicious": True, "source": "local", "reason": "Multicast IP in ARP", "score": 70}

            # Link-local — could indicate APIPA / misconfiguration
            if addr.is_link_local:
                return {"malicious": True, "source": "local", "reason": "Link-local IP (APIPA) — unconfigured device", "score": 45}

            # Unspecified
            if addr == ipaddress.ip_address("0.0.0.0"):
                return {"malicious": True, "source": "local", "reason": "Unspecified IP address in ARP", "score": 90}

        except ValueError:
            return {"malicious": True, "source": "local", "reason": "Invalid IP format", "score": 95}

        return None

    # ── ABUSEIPDB ─────────────────────────────
    def _check_abuseipdb(self, ip: str) -> dict | None:
        """
        AbuseIPDB API v2 — checks if IP has been reported for abuse.
        Free tier: 1000 checks/day
        Get key at: https://www.abuseipdb.com/api
        """
        try:
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=30&verbose"
            req = urllib.request.Request(url)
            req.add_header("Key", self.config.abuseipdb_key)
            req.add_header("Accept", "application/json")

            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())

            self._request_count += 1
            abuse_score = data["data"].get("abuseConfidenceScore", 0)
            is_tor       = data["data"].get("isTor", False)
            country      = data["data"].get("countryCode", "??")
            reports      = data["data"].get("totalReports", 0)
            domain       = data["data"].get("domain", "")
            isp          = data["data"].get("isp", "")

            if abuse_score >= 25 or is_tor:
                reason = f"AbuseIPDB score {abuse_score}/100"
                if is_tor:
                    reason += " (Tor exit node)"
                if reports > 0:
                    reason += f" | {reports} abuse reports"
                return {
                    "malicious": True,
                    "source": "AbuseIPDB",
                    "reason": reason,
                    "score": min(abuse_score + 20, 100),
                    "country": country,
                    "isp": isp,
                    "domain": domain,
                    "is_tor": is_tor,
                }
            logger.debug(f"[ThreatIntel] AbuseIPDB: {ip} is clean (score={abuse_score})")

        except Exception as e:
            logger.debug(f"[ThreatIntel] AbuseIPDB error for {ip}: {e}")

        return None

    # ── VIRUSTOTAL ────────────────────────────
    def _check_virustotal(self, ip: str) -> dict | None:
        """
        VirusTotal API v3 — checks IP reputation across 70+ antivirus engines.
        Free tier: 500 requests/day
        Get key at: https://www.virustotal.com/gui/my-apikey
        """
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            req = urllib.request.Request(url)
            req.add_header("x-apikey", self.config.virustotal_key)

            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read())

            self._request_count += 1
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious  = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless   = stats.get("harmless", 0)
            total = malicious + suspicious + harmless

            reputation = data["data"]["attributes"].get("reputation", 0)
            country    = data["data"]["attributes"].get("country", "??")
            asn        = data["data"]["attributes"].get("asn", "")
            as_owner   = data["data"]["attributes"].get("as_owner", "")

            if malicious >= 2 or (malicious >= 1 and reputation < -10):
                score = min(int((malicious / max(total, 1)) * 100) + 30, 100)
                return {
                    "malicious": True,
                    "source": "VirusTotal",
                    "reason": f"{malicious}/{total} AV engines flagged as malicious",
                    "score": score,
                    "country": country,
                    "asn": asn,
                    "as_owner": as_owner,
                    "reputation": reputation,
                    "detections": malicious,
                }
            logger.debug(f"[ThreatIntel] VirusTotal: {ip} clean ({malicious} detections)")

        except Exception as e:
            logger.debug(f"[ThreatIntel] VirusTotal error for {ip}: {e}")

        return None

    # ── CACHE ─────────────────────────────────
    def _get_cache(self, ip: str) -> dict | None:
        with self._lock:
            entry = self._cache.get(ip)
            if entry:
                if datetime.now() - entry["ts"] < self._cache_ttl:
                    return entry["data"]
                del self._cache[ip]
        return None

    def _set_cache(self, ip: str, data: dict):
        with self._lock:
            self._cache[ip] = {"data": data, "ts": datetime.now()}
