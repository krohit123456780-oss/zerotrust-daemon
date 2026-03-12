"""
detectors/port_scanner_detector.py

Two jobs:
1. Scan newly detected devices for risky open ports
2. Detect if a device ON the network is port-scanning others
   (behavior of worms, ransomware, network propagation attacks)
"""

import socket
import time
import threading
import logging
from collections import defaultdict
from datetime import datetime

logger = logging.getLogger("daemon")


class PortScanDetector:
    def __init__(self, config, registry, on_threat_cb):
        self.config = config
        self.registry = registry
        self.on_threat = on_threat_cb
        self.running = False

        # Track connection attempts per source IP to detect scanning behavior
        # {src_ip: [timestamps of distinct dst_port attempts]}
        self._scan_tracker: dict[str, list] = defaultdict(list)
        self._scan_window = 10    # seconds
        self._scan_threshold = 15 # distinct ports in window = port scanner

    def start(self):
        self.running = True
        logger.info("[PortScan] Detector started")

        try:
            from scapy.all import sniff, TCP, IP
            logger.info("[PortScan] Live SYN scan detection active")
            sniff(
                filter="tcp",
                prn=self._handle_tcp_packet,
                iface=self.config.interface,
                stop_filter=lambda _: not self.running,
                store=False,
            )
        except Exception as e:
            logger.warning(f"[PortScan] Live detection unavailable: {e}")
            # Fall back to passive port checks on registry updates
            self._passive_mode()

    def stop(self):
        self.running = False

    # ── LIVE TCP MONITORING ───────────────────
    def _handle_tcp_packet(self, packet):
        """Detect port-scanning behavior from internal devices."""
        try:
            from scapy.all import TCP, IP
            if not (packet.haslayer(IP) and packet.haslayer(TCP)):
                return

            # SYN packets (connection attempts) with no ACK = scan probe
            flags = packet[TCP].flags
            if flags != 0x02:  # SYN only
                return

            src_ip = packet[IP].src
            dst_port = packet[TCP].dport

            # Ignore external IPs — we only care about internal scanners
            if not self._is_local_ip(src_ip):
                return

            now = time.time()
            attempts = self._scan_tracker[src_ip]
            attempts.append((now, dst_port))

            # Remove old entries outside the window
            self._scan_tracker[src_ip] = [
                (t, p) for t, p in attempts if now - t < self._scan_window
            ]

            distinct_ports = len(set(p for _, p in self._scan_tracker[src_ip]))

            if distinct_ports >= self._scan_threshold:
                device = self.registry.get_by_ip(src_ip) or {"ip": src_ip, "mac": "unknown", "name": src_ip}
                logger.warning(f"[PortScan] {src_ip} scanned {distinct_ports} ports in {self._scan_window}s — possible worm/malware")
                self.on_threat(
                    device,
                    reason=f"Port scanning detected: {distinct_ports} ports probed in {self._scan_window}s",
                    severity="HIGH"
                )
                # Reset tracker for this IP
                self._scan_tracker[src_ip] = []

        except Exception:
            pass

    # ── DEVICE PORT SCAN (on new device join) ──
    def scan_device_ports(self, ip: str) -> list[int]:
        """
        Quick port scan of a newly joined device.
        Returns list of open ports found.
        """
        open_ports = []
        ports = self.config.ports_to_check

        def check_port(port):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.config.port_scan_timeout)
                result = s.connect_ex((ip, port))
                s.close()
                if result == 0:
                    open_ports.append(port)
            except Exception:
                pass

        threads = [threading.Thread(target=check_port, args=(p,)) for p in ports]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=2)

        if open_ports:
            logger.info(f"[PortScan] {ip} open ports: {open_ports}")

        return open_ports

    # ── PASSIVE MODE (no Scapy) ───────────────
    def _passive_mode(self):
        """
        Without Scapy, periodically scan known devices for new open ports.
        Less real-time but still useful.
        """
        logger.info("[PortScan] Running in passive port-check mode")
        while self.running:
            for device in self.registry.verified_devices():
                ip = device.get("ip")
                if not ip:
                    continue
                open_ports = self.scan_device_ports(ip)
                if open_ports != device.get("open_ports", []):
                    device["open_ports"] = open_ports
                    self.registry.update_device(device)

                    # Check new risky ports
                    from detectors.threat_intel import MALWARE_PORT_SIGNATURES
                    for p in open_ports:
                        if p in MALWARE_PORT_SIGNATURES:
                            self.on_threat(
                                device,
                                reason=f"Malware port {p} opened: {MALWARE_PORT_SIGNATURES[p]}",
                                severity="HIGH"
                            )
                            break

            time.sleep(120)  # Check every 2 minutes

    def _is_local_ip(self, ip: str) -> bool:
        """Check if IP is in private/local range."""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            first = int(parts[0])
            second = int(parts[1])
            return (
                first == 10 or
                (first == 172 and 16 <= second <= 31) or
                (first == 192 and second == 168)
            )
        except ValueError:
            return False
