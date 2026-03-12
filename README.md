# ZeroTrust Network Security Daemon

A real, cross-platform daemon that monitors your network and automatically
detects + blocks threats when any device connects — wired OR wireless.

---

## What It Actually Does

| Feature | How |
|---|---|
| Detects every device that joins | ARP packet sniffing (live) + periodic ARP sweep |
| Checks against virus databases | VirusTotal API (70+ AV engines) + AbuseIPDB |
| Detects malware C2 beaconing | Traffic pattern analysis (regular-interval connections) |
| Detects port scanning (worms) | TCP SYN packet monitoring — flags devices scanning others |
| Detects ARP spoofing (MitM) | ARP table change monitoring |
| Detects DDoS participation | Packets-per-second monitoring |
| Detects DNS tunneling | Oversized DNS query detection |
| Auto-blocks threats | iptables (Linux) / pf (macOS) / netsh (Windows) |
| Works on wired + wireless | Monitors at the network layer — connection type doesn't matter |
| Persistent device registry | Remembers all devices across restarts |
| Live terminal dashboard | Curses-based real-time UI |

---

## What It CANNOT Do

- It **cannot scan files inside** other devices (no agent on those devices)
- It detects threats **by their network behavior**, not by scanning their hard drive
- It is a **network-level guardian** — complement it with antivirus on each device

---

## Installation

### Linux (recommended — Raspberry Pi / Ubuntu / Debian)

```bash
# Install system dependencies
sudo apt update
sudo apt install python3-pip python3-dev libpcap-dev iptables

# Install Python dependencies
sudo pip3 install -r requirements.txt

# Run the daemon
sudo python3 daemon.py --ui
```

### macOS

```bash
# Install Homebrew if needed: https://brew.sh
brew install python3 libpcap

# Install Python dependencies
sudo pip3 install -r requirements.txt

# Run the daemon
sudo python3 daemon.py --ui
```

### Windows (run as Administrator)

```powershell
# 1. Install Npcap from https://npcap.com/ (required for Scapy)
# 2. Open PowerShell as Administrator
pip install -r requirements.txt

# Run the daemon
python daemon.py --ui
```

---

## Usage

```bash
# Basic — monitor all interfaces, auto-detect everything
sudo python3 daemon.py

# With live terminal UI
sudo python3 daemon.py --ui

# Specify a network interface
sudo python3 daemon.py --interface eth0       # wired
sudo python3 daemon.py --interface wlan0      # wireless

# Add threat intelligence (free API keys)
sudo python3 daemon.py \
  --virustotal-key YOUR_VT_KEY \
  --abuseipdb-key YOUR_ABUSE_KEY

# Log-only mode (detect but don't block — for testing)
# Edit core/config.py and set firewall_enabled = False

# Adjust auto-block sensitivity (default: block if risk >= 60)
sudo python3 daemon.py --auto-block-threshold 40
```

---

## Getting Free API Keys (Optional but Recommended)

### VirusTotal (checks IPs against 70+ antivirus engines)
1. Go to https://www.virustotal.com/gui/join-us
2. Create free account
3. Go to https://www.virustotal.com/gui/my-apikey
4. Copy your API key
5. Free tier: 500 requests/day

### AbuseIPDB (checks IPs against abuse reports database)
1. Go to https://www.abuseipdb.com/register
2. Create free account
3. Go to https://www.abuseipdb.com/account/api
4. Create a key
5. Free tier: 1000 requests/day

---

## Whitelist Your Own Devices

Edit `core/config.py` and add your device MACs to prevent accidental blocking:

```python
self.mac_whitelist = {
    "AA:BB:CC:DD:EE:FF",   # Your laptop
    "11:22:33:44:55:66",   # Your phone
}
```

---

## Architecture

```
daemon.py                    ← Main process (PID manager)
├── core/
│   ├── config.py            ← All settings
│   ├── logger.py            ← Log to file + console
│   └── device_registry.py  ← Persistent device store (JSON)
├── detectors/
│   ├── arp_monitor.py       ← Detects new devices (wired + wireless)
│   ├── threat_intel.py      ← VirusTotal + AbuseIPDB + local checks
│   ├── port_scanner_detector.py  ← Port scan detection (both ways)
│   └── traffic_analyzer.py ← Beaconing, DDoS, ARP spoof, DNS tunnel
├── blockers/
│   └── firewall.py          ← iptables / pf / netsh blocking
└── ui/
    └── terminal_ui.py       ← Live curses dashboard
```

---

## Run as a System Service (Linux — auto-start on boot)

```bash
# Create systemd service
sudo nano /etc/systemd/system/zerotrust.service
```

Paste:
```ini
[Unit]
Description=ZeroTrust Network Security Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/zerotrust-daemon/daemon.py
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable zerotrust
sudo systemctl start zerotrust
sudo systemctl status zerotrust

# View live logs
sudo journalctl -u zerotrust -f
```

---

## Log File

All events are written to `zerotrust.log`:

```
2026-03-13 14:22:01  INFO     [NEW DEVICE] iPhone — IP: 192.168.1.45  MAC: AA:BB:CC:DD:EE:FF
2026-03-13 14:22:02  WARNING  [THREAT INTEL] 192.168.1.45 flagged: AbuseIPDB score 87/100
2026-03-13 14:22:02  CRITICAL [BLOCKED] 192.168.1.45 | Reason: AbuseIPDB score 87 | Severity: HIGH
2026-03-13 14:25:11  CRITICAL [BEACON] 192.168.1.33 → 185.220.101.x every ~30.0s — malware C2
2026-03-13 14:31:44  WARNING  [PortScan] 192.168.1.22 scanned 47 ports in 10s — possible worm
```
