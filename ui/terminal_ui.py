"""
ui/terminal_ui.py
Live terminal dashboard using curses.
Run with: sudo python3 daemon.py --ui
"""

try:
    import curses
    CURSES_AVAILABLE = True
except ImportError:
    CURSES_AVAILABLE = False

import threading
import time
import logging
from datetime import datetime
from collections import deque

logger = logging.getLogger("daemon")


class TerminalUI:
    def __init__(self, config, registry):
        self.config = config
        self.registry = registry
        self.alerts = deque(maxlen=20)
        self._lock = threading.Lock()
        self.screen = None

    def add_alert(self, severity: str, ip: str, reason: str):
        with self._lock:
            self.alerts.appendleft({
                "time": datetime.now().strftime("%H:%M:%S"),
                "severity": severity,
                "ip": ip,
                "reason": reason[:50]
            })

    def refresh(self):
        pass  # curses redraws on its own loop

    def run(self):
        try:
            curses.wrapper(self._main)
        except Exception as e:
            logger.debug(f"[UI] Terminal UI error: {e}")

    def _main(self, stdscr):
        self.screen = stdscr
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_GREEN,  -1)
        curses.init_pair(2, curses.COLOR_RED,    -1)
        curses.init_pair(3, curses.COLOR_YELLOW, -1)
        curses.init_pair(4, curses.COLOR_CYAN,   -1)
        curses.init_pair(5, curses.COLOR_WHITE,  -1)
        curses.curs_set(0)
        stdscr.nodelay(True)

        while True:
            try:
                stdscr.clear()
                h, w = stdscr.getmaxyx()
                self._draw(stdscr, h, w)
                stdscr.refresh()
                time.sleep(1)
                key = stdscr.getch()
                if key == ord('q'):
                    break
            except curses.error:
                pass

    def _draw(self, s, h, w):
        GREEN  = curses.color_pair(1) | curses.A_BOLD
        RED    = curses.color_pair(2) | curses.A_BOLD
        YELLOW = curses.color_pair(3) | curses.A_BOLD
        CYAN   = curses.color_pair(4) | curses.A_BOLD
        WHITE  = curses.color_pair(5)

        # Header
        title = "[ ZEROTRUST NETWORK SECURITY DAEMON ]"
        s.addstr(0, (w - len(title)) // 2, title, CYAN | curses.A_BOLD)
        s.addstr(1, 0, "─" * w, WHITE)

        # Stats row
        devices = self.registry.all_devices()
        verified = len([d for d in devices if d.get("status") == "VERIFIED"])
        blocked  = len([d for d in devices if d.get("status") == "BLOCKED"])
        pending  = len([d for d in devices if d.get("status") == "PENDING"])

        s.addstr(2, 2,  f"VERIFIED: {verified}", GREEN)
        s.addstr(2, 20, f"PENDING: {pending}",   YELLOW)
        s.addstr(2, 38, f"BLOCKED: {blocked}",   RED)
        s.addstr(2, 56, f"TIME: {datetime.now().strftime('%H:%M:%S')}", WHITE)
        s.addstr(3, 0, "─" * w, WHITE)

        # Device list (left half)
        mid = w // 2
        s.addstr(4, 2, "DEVICES", CYAN)
        s.addstr(4, mid + 2, "ALERTS", CYAN)
        s.addstr(5, 0, "─" * mid, WHITE)
        s.addstr(5, mid, "─" * (w - mid), WHITE)

        row = 6
        for device in devices[:h - 10]:
            if row >= h - 3:
                break
            status = device.get("status", "PENDING")
            color = GREEN if status == "VERIFIED" else RED if status == "BLOCKED" else YELLOW
            name = (device.get("name") or "Unknown")[:18]
            ip   = device.get("ip", "")[:15]
            risk = device.get("risk_score", 0)
            line = f" {name:<18} {ip:<15} [{status:<9}] risk={risk:3}"
            try:
                s.addstr(row, 0, line[:mid-1], color)
            except curses.error:
                pass
            row += 1

        # Alerts (right half)
        alert_row = 6
        with self._lock:
            for alert in list(self.alerts)[:h - 10]:
                if alert_row >= h - 3:
                    break
                sev = alert["severity"]
                color = RED if sev in ("CRITICAL", "HIGH") else YELLOW if sev == "MEDIUM" else WHITE
                line = f" {alert['time']} [{sev:<8}] {alert['ip']}"
                reason = f"   {alert['reason']}"
                try:
                    s.addstr(alert_row,     mid, line[:w-mid-1],   color)
                    s.addstr(alert_row + 1, mid, reason[:w-mid-1], WHITE)
                except curses.error:
                    pass
                alert_row += 2

        # Footer
        s.addstr(h - 2, 0, "─" * w, WHITE)
        footer = f" Interface: {self.config.interface or 'auto'} | Press Q to quit "
        s.addstr(h - 1, 0, footer, WHITE)
