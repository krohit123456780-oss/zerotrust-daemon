"""
detectors/arp_monitor.py

Monitors ARP traffic to detect every device that joins the network,
whether wired (Ethernet) or wireless (Wi-Fi).

How it works:
  - Sniffs ARP "who-has" and "is-at" packets using Scapy
  - Every new MAC/IP pair triggers the on_new_device callback
  - Falls back to periodic ARP sweep if live sniffing fails
"""

import time
import socket
import threading
import subprocess
import platform
import logging
from datetime import datetime

logger = logging.getLogger("daemon")

try:
    from scapy.all import ARP, Ether, srp, sniff, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("[ARP] Scapy not installed — using fallback ARP scanner")


class ARPMonitor:
    def __init__(self, config, registry, on_new_device_cb):
        self.config = config
        self.registry = registry
        self.on_new_device = on_new_device_cb
        self.running = False
        self._seen_macs = set()

        # Pre-load from registry so we don't re-alert known devices
        for d in registry.all_devices():
            mac = d.get("mac", "").upper()
            if mac:
                self._seen_macs.add(mac)

    # ── PUBLIC ────────────────────────────────
    def start(self):
        self.running = True
        logger.info(f"[ARP] Monitor starting on interface: {self.config.interface}")

        if SCAPY_AVAILABLE:
            self._start_scapy_sniffer()
        else:
            self._start_fallback_scanner()

    def stop(self):
        self.running = False

    # ── SCAPY LIVE SNIFF ──────────────────────
    def _start_scapy_sniffer(self):
        """
        Live ARP packet sniffing — catches devices the instant they
        send ANY ARP packet (request or reply).
        """
        logger.info("[ARP] Live ARP sniffing active (wired + wireless)")

        # Also run a periodic sweep in background
        sweep_thread = threading.Thread(
            target=self._periodic_sweep, daemon=True, name="ARP-Sweep"
        )
        sweep_thread.start()

        try:
            sniff(
                filter="arp",
                prn=self._handle_arp_packet,
                iface=self.config.interface,
                stop_filter=lambda _: not self.running,
                store=False,
            )
        except Exception as e:
            logger.warning(f"[ARP] Sniff failed: {e} — falling back to sweep")
            self._start_fallback_scanner()

    def _handle_arp_packet(self, packet):
        """Process a captured ARP packet."""
        if not (packet.haslayer(ARP) and packet[ARP].op in (1, 2)):
            return

        ip  = packet[ARP].psrc
        mac = packet[ARP].hwsrc.upper()

        if not ip or ip.startswith("0.0.0.0"):
            return
        if mac in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
            return
        if ip in self.config.ip_whitelist:
            return
        if mac in self.config.mac_whitelist:
            return

        if mac not in self._seen_macs:
            self._seen_macs.add(mac)
            device = self._build_device(ip, mac)
            self.registry.update_device(device)
            self.on_new_device(device)

    # ── PERIODIC SWEEP ────────────────────────
    def _periodic_sweep(self):
        """ARP sweep every N seconds to catch devices that missed live sniff."""
        while self.running:
            time.sleep(self.config.scan_interval)
            self._arp_sweep()

    def _arp_sweep(self):
        """Send ARP requests to the whole subnet."""
        subnet = self._get_subnet()
        logger.debug(f"[ARP] Sweeping subnet {subnet}")
        try:
            answered, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
                timeout=2,
                verbose=False,
                iface=self.config.interface,
            )
            for _, rcv in answered:
                ip  = rcv[ARP].psrc
                mac = rcv[ARP].hwsrc.upper()
                if mac not in self._seen_macs:
                    self._seen_macs.add(mac)
                    device = self._build_device(ip, mac)
                    self.registry.update_device(device)
                    self.on_new_device(device)
        except Exception as e:
            logger.debug(f"[ARP] Sweep error: {e}")

    # ── FALLBACK (no Scapy) ───────────────────
    def _start_fallback_scanner(self):
        """
        Fallback using system ping sweep + arp table parsing.
        Works on Linux/macOS/Windows without Scapy.
        """
        logger.info("[ARP] Using system ARP fallback scanner")
        while self.running:
            self._system_arp_scan()
            time.sleep(self.config.scan_interval)

    def _system_arp_scan(self):
        system = platform.system()
        try:
            if system == "Windows":
                out = subprocess.check_output(["arp", "-a"], text=True)
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) >= 2:
                        ip  = parts[0]
                        mac = parts[1].replace("-", ":").upper()
                        self._process_fallback(ip, mac)
            else:
                # Ping sweep first to populate ARP table
                subnet = self._get_subnet().replace("/24", "")
                base = ".".join(subnet.split(".")[:3])
                for i in range(1, 255):
                    ip = f"{base}.{i}"
                    subprocess.Popen(
                        ["ping", "-c1", "-W1", ip],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                time.sleep(3)

                out = subprocess.check_output(["arp", "-n"], text=True)
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) >= 3 and ":" in parts[2]:
                        ip  = parts[0]
                        mac = parts[2].upper()
                        self._process_fallback(ip, mac)
        except Exception as e:
            logger.debug(f"[ARP] Fallback scan error: {e}")

    def _process_fallback(self, ip: str, mac: str):
        if not ip or not mac:
            return
        if ip in self.config.ip_whitelist:
            return
        if mac in self.config.mac_whitelist:
            return
        if mac in ("FF:FF:FF:FF:FF:FF", "<incomplete>".upper()):
            return
        if mac not in self._seen_macs:
            self._seen_macs.add(mac)
            device = self._build_device(ip, mac)
            self.registry.update_device(device)
            self.on_new_device(device)

    # ── HELPERS ───────────────────────────────
    def _build_device(self, ip: str, mac: str) -> dict:
        """Create a device record from IP + MAC."""
        hostname = self._resolve_hostname(ip)
        vendor   = self._lookup_vendor(mac)
        return {
            "ip":         ip,
            "mac":        mac.upper(),
            "name":       hostname or vendor or "Unknown Device",
            "hostname":   hostname,
            "vendor":     vendor,
            "status":     "PENDING",
            "risk_score": 0,
            "first_seen": datetime.now().isoformat(),
            "last_seen":  datetime.now().isoformat(),
            "connection": self._detect_connection_type(),
        }

    def _resolve_hostname(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ""

    def _lookup_vendor(self, mac: str) -> str:
        """Basic OUI vendor lookup from a built-in table."""
        OUI_TABLE = {
            "B8:27:EB": "Raspberry Pi",
            "DC:A6:32": "Raspberry Pi",
            "18:B4:30": "Nest Labs",
            "44:65:0D": "Amazon (Echo)",
            "F0:F6:1C": "Amazon",
            "00:0C:29": "VMware VM",
            "00:50:56": "VMware VM",
            "08:00:27": "VirtualBox VM",
            "AC:DE:48": "Apple",
            "A4:C3:F0": "Apple iPhone",
            "3C:22:FB": "Apple",
            "74:75:48": "Sonos",
            "50:C7:BF": "TP-Link",
            "FC:EC:DA": "Ubiquiti",
            "00:1A:11": "Google",
            "54:60:09": "Google",
            "94:9F:3E": "Samsung",
            "8C:79:F5": "Samsung",
            "00:16:3E": "Xen VM",
        }
        oui = mac[:8].upper()
        return OUI_TABLE.get(oui, "")

    def _get_subnet(self) -> str:
        """Get local subnet in CIDR notation."""
        try:
            import netifaces
            iface = self.config.interface
            if iface:
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    addr = addrs[netifaces.AF_INET][0]
                    ip   = addr["addr"]
                    mask = addr.get("netmask", "255.255.255.0")
                    base = ".".join(ip.split(".")[:3]) + ".0"
                    return f"{base}/24"
        except Exception:
            pass
        return "192.168.1.0/24"

    def _detect_connection_type(self) -> str:
        """Guess if monitoring wired or wireless interface."""
        iface = self.config.interface or ""
        if any(w in iface.lower() for w in ["wlan", "wifi", "wi", "wl", "en0", "en1"]):
            return "wireless"
        return "wired"
