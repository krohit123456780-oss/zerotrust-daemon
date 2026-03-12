"""
blockers/firewall.py

Cross-platform firewall blocking:
  - Linux  : iptables / nftables
  - macOS  : pfctl (pf firewall)
  - Windows: netsh advfirewall

Blocks at the OS firewall level — the device CANNOT communicate
with the network until the rule is removed.
"""

import sys
import subprocess
import logging
import platform
from datetime import datetime

logger = logging.getLogger("daemon")


class FirewallBlocker:
    def __init__(self, config):
        self.config = config
        self.platform = platform.system()  # 'Linux', 'Darwin', 'Windows'
        self._blocked_ips: set[str] = set()
        self._blocked_macs: set[str] = set()

        if not config.firewall_enabled:
            logger.info("[Firewall] Firewall blocking DISABLED (log-only mode)")

    # ── PUBLIC ────────────────────────────────
    def block_ip(self, ip: str) -> bool:
        """Block all traffic from an IP address."""
        if not self.config.firewall_enabled:
            logger.info(f"[Firewall] LOG-ONLY: Would block {ip}")
            return True

        if ip in self._blocked_ips:
            return True  # Already blocked

        if ip in self.config.ip_whitelist:
            logger.warning(f"[Firewall] Refused to block whitelisted IP {ip}")
            return False

        success = False
        if self.platform == "Linux":
            success = self._iptables_block(ip)
        elif self.platform == "Darwin":
            success = self._pf_block(ip)
        elif self.platform == "Windows":
            success = self._netsh_block(ip)
        else:
            logger.error(f"[Firewall] Unsupported platform: {self.platform}")
            return False

        if success:
            self._blocked_ips.add(ip)
            logger.info(f"[Firewall] {ip} BLOCKED at OS firewall level")
        return success

    def block_mac(self, mac: str) -> bool:
        """
        Block by MAC address (Linux only via arptables/ebtables).
        More persistent than IP blocking for dynamic IPs.
        """
        if not self.config.firewall_enabled:
            logger.info(f"[Firewall] LOG-ONLY: Would block MAC {mac}")
            return True

        if self.platform != "Linux":
            logger.debug("[Firewall] MAC blocking only supported on Linux")
            return False

        try:
            subprocess.run(
                ["arptables", "-A", "INPUT", "--source-mac", mac, "-j", "DROP"],
                check=True, capture_output=True
            )
            self._blocked_macs.add(mac)
            logger.info(f"[Firewall] MAC {mac} blocked via arptables")
            return True
        except subprocess.CalledProcessError as e:
            logger.debug(f"[Firewall] arptables failed: {e.stderr.decode()}")
            # Try ebtables as fallback
            try:
                subprocess.run(
                    ["ebtables", "-A", "INPUT", "-s", mac, "-j", "DROP"],
                    check=True, capture_output=True
                )
                return True
            except Exception:
                return False

    def unblock_ip(self, ip: str) -> bool:
        """Remove an IP block (for manual remediation)."""
        if ip not in self._blocked_ips:
            return True

        success = False
        if self.platform == "Linux":
            success = self._iptables_unblock(ip)
        elif self.platform == "Darwin":
            success = self._pf_unblock(ip)
        elif self.platform == "Windows":
            success = self._netsh_unblock(ip)

        if success:
            self._blocked_ips.discard(ip)
            logger.info(f"[Firewall] {ip} UNBLOCKED")
        return success

    def list_blocked(self) -> list[str]:
        return list(self._blocked_ips)

    # ── LINUX: iptables ───────────────────────
    def _iptables_block(self, ip: str) -> bool:
        """Drop all packets from IP using iptables."""
        try:
            # Block incoming
            subprocess.run(
                ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True
            )
            # Block outgoing to IP
            subprocess.run(
                ["iptables", "-I", "OUTPUT", "1", "-d", ip, "-j", "DROP"],
                check=True, capture_output=True
            )
            # Block forwarding (in case we're a gateway)
            subprocess.run(
                ["iptables", "-I", "FORWARD", "1", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True
            )
            return True
        except subprocess.CalledProcessError as e:
            # Try nftables as fallback
            return self._nftables_block(ip)
        except FileNotFoundError:
            return self._nftables_block(ip)

    def _nftables_block(self, ip: str) -> bool:
        """nftables alternative for modern Linux systems."""
        try:
            subprocess.run(
                ["nft", "add", "rule", "inet", "filter", "input",
                 "ip", "saddr", ip, "drop"],
                check=True, capture_output=True
            )
            return True
        except Exception as e:
            logger.error(f"[Firewall] nftables block failed: {e}")
            return False

    def _iptables_unblock(self, ip: str) -> bool:
        try:
            subprocess.run(["iptables", "-D", "INPUT",  "-s", ip, "-j", "DROP"], capture_output=True)
            subprocess.run(["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"], capture_output=True)
            subprocess.run(["iptables", "-D", "FORWARD","-s", ip, "-j", "DROP"], capture_output=True)
            return True
        except Exception:
            return False

    # ── macOS: pf ─────────────────────────────
    def _pf_block(self, ip: str) -> bool:
        """Add an IP to pf's block table."""
        try:
            # Add to the persistent pf table
            subprocess.run(
                ["pfctl", "-t", "zerotrust_blocked", "-T", "add", ip],
                check=True, capture_output=True
            )
            # Make sure the table has a block rule (idempotent)
            self._ensure_pf_rules()
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"[Firewall] pfctl error: {e.stderr.decode()}")
            return False

    def _ensure_pf_rules(self):
        """Make sure pf has a rule to block the zerotrust_blocked table."""
        rule = 'table <zerotrust_blocked> persist\nblock drop in quick from <zerotrust_blocked>\n'
        try:
            with open("/etc/pf.anchors/zerotrust", "w") as f:
                f.write(rule)
            subprocess.run(["pfctl", "-a", "zerotrust", "-f", "/etc/pf.anchors/zerotrust"],
                           capture_output=True)
            subprocess.run(["pfctl", "-e"], capture_output=True)  # enable pf
        except Exception as e:
            logger.debug(f"[Firewall] pf anchor setup: {e}")

    def _pf_unblock(self, ip: str) -> bool:
        try:
            subprocess.run(
                ["pfctl", "-t", "zerotrust_blocked", "-T", "delete", ip],
                check=True, capture_output=True
            )
            return True
        except Exception:
            return False

    # ── WINDOWS: netsh ────────────────────────
    def _netsh_block(self, ip: str) -> bool:
        """Create Windows Firewall rules to block IP."""
        rule_name = f"ZeroTrust_Block_{ip.replace('.', '_')}"
        try:
            # Block inbound
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}_IN",
                "dir=in", "action=block",
                f"remoteip={ip}",
                "enable=yes"
            ], check=True, capture_output=True)
            # Block outbound
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}_OUT",
                "dir=out", "action=block",
                f"remoteip={ip}",
                "enable=yes"
            ], check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"[Firewall] netsh error: {e.stderr.decode() if e.stderr else str(e)}")
            return False

    def _netsh_unblock(self, ip: str) -> bool:
        rule_name = f"ZeroTrust_Block_{ip.replace('.', '_')}"
        try:
            subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                            f"name={rule_name}_IN"], capture_output=True)
            subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                            f"name={rule_name}_OUT"], capture_output=True)
            return True
        except Exception:
            return False

    def cleanup_all(self):
        """Remove all daemon-added firewall rules on shutdown."""
        logger.info(f"[Firewall] Cleaning up {len(self._blocked_ips)} block rules...")
        for ip in list(self._blocked_ips):
            self.unblock_ip(ip)
