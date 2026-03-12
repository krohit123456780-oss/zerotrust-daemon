#!/usr/bin/env python3
"""
ZeroTrust Network Security Daemon
Cross-platform: Linux, Windows, macOS
Detects threats on both wired and wireless connections.

Usage:
    sudo python3 daemon.py              # Run daemon
    sudo python3 daemon.py --ui         # Run with live terminal UI
    sudo python3 daemon.py --interface eth0  # Specific interface
"""

import sys
import os
import time
import signal
import argparse
import threading
import logging
from datetime import datetime

# Local modules
from core.config import Config
from core.logger import setup_logger
from core.device_registry import DeviceRegistry
from detectors.arp_monitor import ARPMonitor
from detectors.port_scanner_detector import PortScanDetector
from detectors.threat_intel import ThreatIntelChecker
from detectors.traffic_analyzer import TrafficAnalyzer
from blockers.firewall import FirewallBlocker
try:
    from ui.terminal_ui import TerminalUI
except Exception:
    TerminalUI = None

# ─────────────────────────────────────────────
#  DAEMON CORE
# ─────────────────────────────────────────────
class ZeroTrustDaemon:
    def __init__(self, config: Config):
        self.config = config
        self.logger = setup_logger("daemon", config.log_file)
        self.running = False

        # Core components
        self.registry    = DeviceRegistry(config)
        self.arp_monitor = ARPMonitor(config, self.registry, self.on_new_device)
        self.port_scan   = PortScanDetector(config, self.registry, self.on_threat)
        self.threat_intel = ThreatIntelChecker(config)
        self.traffic_analyzer = TrafficAnalyzer(config, self.registry, self.on_threat)
        self.firewall    = FirewallBlocker(config)
        self.ui          = TerminalUI(config, self.registry) if config.ui_enabled else None

        self.threats_blocked = 0
        self.devices_seen    = 0
        self.start_time      = None

        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGINT,  self._shutdown)
        signal.signal(signal.SIGTERM, self._shutdown)

    # ── CALLBACKS ──────────────────────────────
    def on_new_device(self, device: dict):
        """Called when a new device appears on the network."""
        self.devices_seen += 1
        ip  = device["ip"]
        mac = device["mac"]
        self.logger.info(f"[NEW DEVICE] {device['name']} — IP: {ip}  MAC: {mac}")

        # Step 1: Check threat intelligence databases
        threat = self.threat_intel.check_ip(ip)
        if threat:
            self.logger.warning(f"[THREAT INTEL] {ip} flagged: {threat['reason']} (score={threat['score']})")
            device["threat"] = threat
            self.on_threat(device, reason=threat["reason"], severity="HIGH")
            return

        # Step 2: Risk-score the device
        risk = self._calculate_risk(device)
        device["risk_score"] = risk

        if risk >= self.config.auto_block_threshold:
            self.logger.warning(f"[AUTO-BLOCK] {ip} risk score {risk} exceeds threshold")
            self.on_threat(device, reason=f"Risk score {risk}/100", severity="HIGH")
        elif risk >= self.config.warn_threshold:
            self.logger.warning(f"[WARN] {ip} elevated risk score {risk}/100")
            device["status"] = "SUSPICIOUS"
            self.registry.update_device(device)
        else:
            device["status"] = "VERIFIED"
            self.registry.update_device(device)
            self.logger.info(f"[ALLOW] {ip} passed verification (risk={risk})")

        if self.ui:
            self.ui.refresh()

    def on_threat(self, device: dict, reason: str, severity: str = "HIGH"):
        """Called when a threat is detected."""
        ip  = device.get("ip", "unknown")
        mac = device.get("mac", "unknown")

        self.threats_blocked += 1
        device["status"] = "BLOCKED"
        device["block_reason"] = reason
        device["blocked_at"] = datetime.now().isoformat()
        self.registry.update_device(device)

        # Block at firewall level
        success = self.firewall.block_ip(ip)
        if success:
            self.logger.critical(
                f"[BLOCKED] {ip} ({mac}) | Reason: {reason} | Severity: {severity}"
            )
        else:
            self.logger.error(f"[BLOCK FAILED] Could not block {ip} — check permissions")

        if self.ui:
            self.ui.add_alert(severity, ip, reason)
            self.ui.refresh()

    # ── RISK SCORING ───────────────────────────
    def _calculate_risk(self, device: dict) -> int:
        """
        Score 0–100. Higher = more dangerous.
        Combines multiple signals.
        """
        score = 0
        mac = device.get("mac", "").upper()
        name = device.get("name", "").lower()

        # Unknown / unresolved hostname
        if name in ("unknown", "", "?"):
            score += 20

        # Randomized MAC address (privacy MAC, common in attacks)
        if mac and self._is_randomized_mac(mac):
            score += 25

        # Check if MAC OUI is from known IoT vendor (lower trust)
        if self._is_iot_oui(mac):
            score += 10

        # New device never seen before
        if not self.registry.has_seen(mac):
            score += 15

        # Open ports (if we have a scan result)
        open_ports = device.get("open_ports", [])
        risky_ports = {22, 23, 3389, 445, 135, 137, 5900, 4444, 1337, 31337}
        for p in open_ports:
            if p in risky_ports:
                score += 10
            else:
                score += 2

        return min(score, 100)

    def _is_randomized_mac(self, mac: str) -> bool:
        """Locally administered (randomized) MACs have bit 1 of first octet set."""
        try:
            first_byte = int(mac.split(":")[0].replace("-",""), 16)
            return bool(first_byte & 0x02)
        except Exception:
            return False

    def _is_iot_oui(self, mac: str) -> bool:
        """Check if MAC belongs to common IoT vendors (lower trust by default)."""
        iot_ouis = {
            "B8:27:EB",  # Raspberry Pi
            "DC:A6:32",  # Raspberry Pi
            "18:B4:30",  # Nest
            "44:65:0D",  # Amazon Echo
            "F0:F6:1C",  # Amazon
            "74:75:48",  # Sonos
            "50:C7:BF",  # TP-Link IoT
        }
        oui = mac[:8].upper()
        return oui in iot_ouis

    # ── LIFECYCLE ──────────────────────────────
    def start(self):
        self.running = True
        self.start_time = datetime.now()
        self.logger.info("=" * 60)
        self.logger.info("  ZeroTrust Daemon STARTING")
        self.logger.info(f"  Platform : {sys.platform}")
        self.logger.info(f"  Interface: {self.config.interface or 'auto-detect'}")
        self.logger.info(f"  Log file : {self.config.log_file}")
        self.logger.info("=" * 60)

        # Check privileges
        if not self._check_privileges():
            self.logger.error("Daemon requires root/admin privileges. Run with sudo.")
            sys.exit(1)

        # Start all detector threads
        threads = [
            threading.Thread(target=self.arp_monitor.start,       daemon=True, name="ARP-Monitor"),
            threading.Thread(target=self.port_scan.start,         daemon=True, name="PortScan-Detector"),
            threading.Thread(target=self.traffic_analyzer.start,  daemon=True, name="Traffic-Analyzer"),
        ]
        for t in threads:
            t.start()
            self.logger.info(f"[THREAD] {t.name} started")

        # Start UI if enabled
        if self.ui:
            ui_thread = threading.Thread(target=self.ui.run, daemon=True, name="Terminal-UI")
            ui_thread.start()

        self.logger.info("[DAEMON] All systems online. Monitoring network...")

        # Keep main thread alive
        try:
            while self.running:
                time.sleep(1)
                self._heartbeat()
        except KeyboardInterrupt:
            self._shutdown(None, None)

    def _heartbeat(self):
        """Periodic health check and stats log."""
        uptime = (datetime.now() - self.start_time).seconds
        if uptime % 60 == 0 and uptime > 0:
            self.logger.info(
                f"[HEARTBEAT] Uptime={uptime}s | "
                f"Devices={self.devices_seen} | "
                f"Blocked={self.threats_blocked} | "
                f"Registry={len(self.registry.devices)}"
            )

    def _shutdown(self, sig, frame):
        self.logger.info("[DAEMON] Shutting down gracefully...")
        self.running = False
        self.arp_monitor.stop()
        self.port_scan.stop()
        self.traffic_analyzer.stop()
        self.registry.save()
        self.logger.info("[DAEMON] Goodbye.")
        sys.exit(0)

    def _check_privileges(self) -> bool:
        """Check if running as root/admin."""
        try:
            return os.geteuid() == 0  # Linux/macOS
        except AttributeError:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0  # Windows


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="ZeroTrust Network Security Daemon")
    parser.add_argument("--interface", "-i", default=None,
                        help="Network interface to monitor (e.g. eth0, wlan0, en0)")
    parser.add_argument("--ui", action="store_true",
                        help="Enable live terminal UI")
    parser.add_argument("--config", "-c", default="config.json",
                        help="Path to config file")
    parser.add_argument("--log", default="zerotrust.log",
                        help="Log file path")
    parser.add_argument("--auto-block-threshold", type=int, default=60,
                        help="Risk score threshold for auto-blocking (0-100)")
    parser.add_argument("--virustotal-key", default=None,
                        help="VirusTotal API key for threat intelligence")
    parser.add_argument("--abuseipdb-key", default=None,
                        help="AbuseIPDB API key for threat intelligence")
    args = parser.parse_args()

    config = Config(
        interface=args.interface,
        ui_enabled=args.ui,
        log_file=args.log,
        auto_block_threshold=args.auto_block_threshold,
        virustotal_key=args.virustotal_key,
        abuseipdb_key=args.abuseipdb_key,
    )

    daemon = ZeroTrustDaemon(config)
    daemon.start()


if __name__ == "__main__":
    main()
