"""
detectors/traffic_analyzer.py

Monitors traffic patterns to detect:
- Malware C2 beaconing (regular intervals = infected device calling home)
- DNS tunneling (data exfiltration via DNS)
- ARP spoofing / Man-in-the-Middle attacks
- Excessive traffic / DDoS participation
- Connections to known malicious ports
"""

import time
import threading
import logging
from collections import defaultdict
from datetime import datetime

logger = logging.getLogger("daemon")

# Beaconing detection: if a device sends traffic to the SAME external IP
# at very regular intervals, it's likely malware calling home.
BEACON_INTERVAL_TOLERANCE = 3.0   # seconds variance allowed
BEACON_MIN_SAMPLES = 5            # need at least 5 samples to conclude
BEACON_MAX_INTERVAL = 300         # ignore intervals > 5 minutes

# DDoS: if a single internal IP generates > N packets/second
DDOS_PPS_THRESHOLD = 500          # packets per second

# DNS tunneling: DNS query/response > 100 bytes is suspicious
DNS_TUNNEL_SIZE_THRESHOLD = 100


class TrafficAnalyzer:
    def __init__(self, config, registry, on_threat_cb):
        self.config = config
        self.registry = registry
        self.on_threat = on_threat_cb
        self.running = False

        # Beaconing tracker: {src_ip: {dst_ip: [timestamps]}}
        self._beacon_tracker: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))

        # Packet rate tracker: {src_ip: [timestamps]}
        self._pps_tracker: dict[str, list] = defaultdict(list)

        # ARP table: {ip: mac} — to detect spoofing
        self._arp_table: dict[str, str] = {}

        self._alerted: set = set()  # prevent duplicate alerts

    def start(self):
        self.running = True
        logger.info("[Traffic] Analyzer starting")

        try:
            from scapy.all import sniff
            logger.info("[Traffic] Deep packet inspection active")

            # Run cleanup in background
            cleanup_thread = threading.Thread(
                target=self._periodic_cleanup, daemon=True, name="Traffic-Cleanup"
            )
            cleanup_thread.start()

            sniff(
                filter="ip or arp",
                prn=self._handle_packet,
                iface=self.config.interface,
                stop_filter=lambda _: not self.running,
                store=False,
            )
        except Exception as e:
            logger.warning(f"[Traffic] Deep inspection unavailable: {e} — running in basic mode")
            self._basic_mode()

    def stop(self):
        self.running = False

    # ── PACKET HANDLER ────────────────────────
    def _handle_packet(self, packet):
        try:
            from scapy.all import IP, TCP, UDP, DNS, ARP, DNSQR

            # ── ARP Spoofing Detection ──────────────
            if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP reply
                ip  = packet[ARP].psrc
                mac = packet[ARP].hwsrc.upper()
                if ip in self._arp_table:
                    if self._arp_table[ip] != mac and ip not in self._alerted:
                        self._alerted.add(ip)
                        device = self.registry.get_by_ip(ip) or {"ip": ip, "mac": mac, "name": ip}
                        logger.critical(f"[ARP SPOOF] {ip} MAC changed {self._arp_table[ip]} → {mac}")
                        self.on_threat(
                            device,
                            reason=f"ARP spoofing detected! MAC changed from {self._arp_table[ip]} to {mac}",
                            severity="CRITICAL"
                        )
                self._arp_table[ip] = mac
                return

            if not packet.haslayer(IP):
                return

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            now = time.time()

            # Only analyze internal source IPs
            if not self._is_local_ip(src_ip):
                return

            # ── DDoS / Flood Detection ──────────────
            self._pps_tracker[src_ip].append(now)
            # Keep only last second
            self._pps_tracker[src_ip] = [
                t for t in self._pps_tracker[src_ip] if now - t < 1.0
            ]
            pps = len(self._pps_tracker[src_ip])

            if pps > DDOS_PPS_THRESHOLD and src_ip not in self._alerted:
                self._alerted.add(src_ip)
                device = self.registry.get_by_ip(src_ip) or {"ip": src_ip, "mac": "unknown", "name": src_ip}
                logger.critical(f"[DDoS] {src_ip} generating {pps} packets/sec")
                self.on_threat(
                    device,
                    reason=f"DDoS/flood detected: {pps} packets/sec — possible botnet participation",
                    severity="CRITICAL"
                )

            # ── Beaconing Detection (C2 malware) ────
            if not self._is_local_ip(dst_ip):  # External destination
                self._beacon_tracker[src_ip][dst_ip].append(now)
                self._check_beaconing(src_ip, dst_ip)

            # ── DNS Tunneling Detection ──────────────
            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                query_len = len(bytes(packet[DNS]))
                if query_len > DNS_TUNNEL_SIZE_THRESHOLD and src_ip not in self._alerted:
                    self._alerted.add(src_ip)
                    device = self.registry.get_by_ip(src_ip) or {"ip": src_ip, "mac": "unknown", "name": src_ip}
                    logger.warning(f"[DNS Tunnel] {src_ip} DNS query size {query_len} bytes — possible data exfiltration")
                    self.on_threat(
                        device,
                        reason=f"DNS tunneling suspected: oversized DNS query ({query_len} bytes)",
                        severity="HIGH"
                    )

            # ── Malware Port Connection ──────────────
            if packet.haslayer(TCP):
                dst_port = packet[TCP].dport
                from detectors.threat_intel import MALWARE_PORT_SIGNATURES
                if dst_port in MALWARE_PORT_SIGNATURES:
                    alert_key = f"{src_ip}:{dst_port}"
                    if alert_key not in self._alerted:
                        self._alerted.add(alert_key)
                        device = self.registry.get_by_ip(src_ip) or {"ip": src_ip, "mac": "unknown", "name": src_ip}
                        logger.warning(f"[Malware Port] {src_ip} → {dst_ip}:{dst_port} ({MALWARE_PORT_SIGNATURES[dst_port]})")
                        self.on_threat(
                            device,
                            reason=f"Connection to malware port {dst_port}: {MALWARE_PORT_SIGNATURES[dst_port]}",
                            severity="HIGH"
                        )

        except Exception:
            pass

    def _check_beaconing(self, src_ip: str, dst_ip: str):
        """Detect regular-interval communication = malware C2 beaconing."""
        timestamps = self._beacon_tracker[src_ip][dst_ip]

        # Need at least N samples and don't re-alert
        if len(timestamps) < BEACON_MIN_SAMPLES:
            return

        alert_key = f"beacon:{src_ip}:{dst_ip}"
        if alert_key in self._alerted:
            return

        # Calculate intervals between connections
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        avg_interval = sum(intervals) / len(intervals)

        # Skip very fast or very slow intervals
        if not (5 <= avg_interval <= BEACON_MAX_INTERVAL):
            return

        # Check if intervals are suspiciously regular (low variance)
        variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
        std_dev = variance ** 0.5

        if std_dev < BEACON_INTERVAL_TOLERANCE:
            self._alerted.add(alert_key)
            device = self.registry.get_by_ip(src_ip) or {
                "ip": src_ip, "mac": "unknown", "name": src_ip
            }
            logger.critical(
                f"[BEACON] {src_ip} → {dst_ip} every ~{avg_interval:.1f}s "
                f"(σ={std_dev:.2f}) — likely malware C2 beacon"
            )
            self.on_threat(
                device,
                reason=f"C2 beaconing to {dst_ip} every {avg_interval:.0f}s — malware suspected",
                severity="CRITICAL"
            )

    def _periodic_cleanup(self):
        """Remove old tracking data to prevent memory bloat."""
        while self.running:
            time.sleep(300)
            cutoff = time.time() - 600
            for src_ip in list(self._beacon_tracker.keys()):
                for dst_ip in list(self._beacon_tracker[src_ip].keys()):
                    self._beacon_tracker[src_ip][dst_ip] = [
                        t for t in self._beacon_tracker[src_ip][dst_ip] if t > cutoff
                    ]
            # Clear alerted set periodically so we can re-alert if still active
            self._alerted = {a for a in self._alerted if "beacon:" not in a}

    def _basic_mode(self):
        """Minimal mode without Scapy — just monitor via netstat periodically."""
        import subprocess, platform
        logger.info("[Traffic] Running in netstat-based basic mode")
        while self.running:
            try:
                system = platform.system()
                if system == "Windows":
                    out = subprocess.check_output(["netstat", "-n"], text=True)
                else:
                    out = subprocess.check_output(["netstat", "-tn"], text=True)

                from detectors.threat_intel import MALWARE_PORT_SIGNATURES
                for line in out.splitlines():
                    for port, desc in MALWARE_PORT_SIGNATURES.items():
                        if f":{port} " in line or f":{port}\t" in line:
                            logger.warning(f"[NetStat] Malware port {port} active: {line.strip()}")
            except Exception as e:
                logger.debug(f"[Traffic] Netstat error: {e}")
            time.sleep(30)

    def _is_local_ip(self, ip: str) -> bool:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            first, second = int(parts[0]), int(parts[1])
            return (first == 10 or
                    (first == 172 and 16 <= second <= 31) or
                    (first == 192 and second == 168))
        except ValueError:
            return False
