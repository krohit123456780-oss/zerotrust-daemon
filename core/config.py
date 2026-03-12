"""
core/config.py — Configuration for ZeroTrust Daemon
"""
import json
import os
import sys

class Config:
    def __init__(
        self,
        interface=None,
        ui_enabled=False,
        log_file="zerotrust.log",
        auto_block_threshold=60,
        warn_threshold=35,
        virustotal_key=None,
        abuseipdb_key=None,
        config_file=None,
    ):
        # Network
        self.interface = interface or self._auto_detect_interface()
        self.scan_interval = 30          # seconds between ARP sweeps
        self.port_scan_timeout = 1.0     # socket timeout for port checks
        self.ports_to_check = [          # ports that get inspected on new devices
            22, 23, 80, 443, 445, 3389,
            5900, 8080, 8443, 4444, 1337,
            31337, 135, 137, 139
        ]

        # Risk thresholds
        self.auto_block_threshold = auto_block_threshold
        self.warn_threshold = warn_threshold

        # Firewall
        self.platform = sys.platform
        self.firewall_enabled = True     # Set False to log-only (no actual blocking)
        self.block_duration = 0          # 0 = permanent until daemon restart

        # Threat intelligence APIs (optional but recommended)
        self.virustotal_key = virustotal_key or os.getenv("VIRUSTOTAL_API_KEY")
        self.abuseipdb_key  = abuseipdb_key  or os.getenv("ABUSEIPDB_API_KEY")

        # Logging & UI
        self.log_file   = log_file
        self.ui_enabled = ui_enabled

        # Persistence
        self.registry_file = "device_registry.json"

        # Whitelist — never block these (add your own devices' MACs)
        self.mac_whitelist = set()
        self.ip_whitelist  = {"127.0.0.1", "::1"}

        # Load from file if provided
        if config_file and os.path.exists(config_file):
            self._load_file(config_file)

    def _auto_detect_interface(self) -> str:
        """Pick the most likely active interface per platform."""
        import socket
        try:
            # Connect to a public IP to find the default interface's address
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
        except Exception:
            ip = "127.0.0.1"

        # Map platform to typical interface names
        if sys.platform.startswith("linux"):
            candidates = ["eth0", "ens33", "ens3", "enp0s3", "wlan0", "wlp2s0"]
        elif sys.platform == "darwin":
            candidates = ["en0", "en1", "en2"]
        else:  # Windows
            return None  # scapy uses Windows GUID names; auto-handled

        try:
            import netifaces
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    for a in addrs[netifaces.AF_INET]:
                        if a.get("addr") == ip:
                            return iface
        except ImportError:
            pass

        for c in candidates:
            return c
        return None

    def _load_file(self, path: str):
        with open(path) as f:
            data = json.load(f)
        for k, v in data.items():
            if hasattr(self, k):
                setattr(self, k, v)

    def to_dict(self) -> dict:
        return {
            "interface": self.interface,
            "scan_interval": self.scan_interval,
            "auto_block_threshold": self.auto_block_threshold,
            "warn_threshold": self.warn_threshold,
            "firewall_enabled": self.firewall_enabled,
            "mac_whitelist": list(self.mac_whitelist),
            "ip_whitelist": list(self.ip_whitelist),
        }

    def save(self, path: str = "config.json"):
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
