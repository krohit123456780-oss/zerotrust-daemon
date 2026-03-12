"""
core/device_registry.py
Persistent store of all devices ever seen on the network.
"""
import json
import os
import threading
from datetime import datetime
from core.config import Config


class DeviceRegistry:
    def __init__(self, config: Config):
        self.config = config
        self.devices: dict[str, dict] = {}   # keyed by MAC address
        self._lock = threading.Lock()
        self._load()

    # ── CRUD ──────────────────────────────────
    def update_device(self, device: dict):
        mac = device.get("mac", "").upper()
        if not mac:
            return
        with self._lock:
            if mac in self.devices:
                self.devices[mac].update(device)
            else:
                device.setdefault("first_seen", datetime.now().isoformat())
                self.devices[mac] = device
            self.devices[mac]["last_seen"] = datetime.now().isoformat()

    def get_by_mac(self, mac: str) -> dict | None:
        return self.devices.get(mac.upper())

    def get_by_ip(self, ip: str) -> dict | None:
        with self._lock:
            for d in self.devices.values():
                if d.get("ip") == ip:
                    return d
        return None

    def has_seen(self, mac: str) -> bool:
        return mac.upper() in self.devices

    def all_devices(self) -> list[dict]:
        with self._lock:
            return list(self.devices.values())

    def blocked_devices(self) -> list[dict]:
        return [d for d in self.all_devices() if d.get("status") == "BLOCKED"]

    def verified_devices(self) -> list[dict]:
        return [d for d in self.all_devices() if d.get("status") == "VERIFIED"]

    # ── PERSISTENCE ───────────────────────────
    def _load(self):
        path = self.config.registry_file
        if os.path.exists(path):
            try:
                with open(path) as f:
                    self.devices = json.load(f)
            except Exception:
                self.devices = {}

    def save(self):
        try:
            with open(self.config.registry_file, "w") as f:
                json.dump(self.devices, f, indent=2)
        except Exception as e:
            pass  # Non-fatal
