# PMKID Attack Tool

A **WiFi penetration testing tool** specifically designed for **PMKID attacks** - a powerful method to crack WiFi passwords without requiring client interaction. This tool automates the entire PMKID attack workflow from network scanning to password cracking.

## 🎯 What is PMKID Attack?

PMKID (Pairwise Master Key Identifier) attack is a WiFi security vulnerability that allows attackers to capture authentication data from access points without needing any connected clients. This makes it particularly effective for penetration testing.

## 🚀 Features

- **🔍 Network Scanning**: Scan and identify available WiFi networks
- **📡 PMKID Capture**: Automatically capture PMKID data from target access points
- **🔓 Password Cracking**: Crack captured PMKID hashes using hashcat
- **📝 Custom Wordlists**: Generate custom password lists using crunch
- **🔄 Monitor Mode Management**: Automatic interface management for monitor mode
- **⚡ Automated Workflow**: Streamlined process from capture to crack

## 📦 Prerequisites

### Required Tools
The tool automatically installs these dependencies:
- `aircrack-ng` - WiFi security auditing
- `hcxtools` - WiFi tools for capturing and converting PMKID
- `hcxdumptool` - PMKID capture tool
- `hashcat` - Password cracking
- `crunch` - Password list generation
- `xterm` - Terminal emulator

### System Requirements
- **Linux** (Kali Linux recommended)
- **Root privileges** (sudo access)
- **Wireless adapter** with monitor mode support

## 🛠️ Installation & Usage

### 1. Clone the Repository
```bash
git clone <repository-url>
cd PMKID-Attack
```

### 2. Run the Tool
```bash
sudo python3 CLI/pmkid-cli.py
```

### 3. Follow the Menu Options
```
(1) PMKID Attack - Step 1: Monitor & Capture PMKID
(2) PMKID Attack - Step 2: Crack PMKID Password
(3) Scan Networks
(4) Create your own passwordlist
(00) Exit
```

## 📋 Step-by-Step Guide

### Step 1: Setup Interface
1. Run the tool: `sudo python3 CLI/pmkid-cli.py`
2. Choose option **1** (PMKID Attack - Step 1)
3. Enter your wireless interface (e.g., `wlp3s0`)
4. The tool will automatically handle interface name changes (e.g., `wlp3s0` → `wlp3s0mon`)

### Step 2: Capture PMKID
1. Scan for available networks
2. Note the **BSSID** and **Channel** of your target
3. Enter the target details when prompted
4. Wait for PMKID capture (press `Ctrl+C` when done)

### Step 3: Crack Password
1. Choose option **2** (PMKID Attack - Step 2)
2. Select your wordlist (rockyou.txt or custom)
3. Wait for hashcat to crack the password

## 🔧 Manual Commands

If you prefer to run commands manually:

```bash
# Find your interface
iw dev

# Start monitor mode
sudo airmon-ng start wlp3s0

# Capture PMKID
sudo hcxdumptool -i wlp3s0mon --enable_status=1 -o pmkid.pcapng --filterlist_ap=TARGET_BSSID --filtermode=2

# Convert to hash format
hcxpcapngtool -o pmkid.22000 pmkid.pcapng

# Crack with hashcat
hashcat -m 22000 pmkid.22000 rockyou.txt

# Show results
hashcat -m 22000 pmkid.22000 rockyou.txt --show
```

## 📁 File Structure

```
PMKID-Attack/
├── CLI/
│   ├── pmkid-cli.py          # Main CLI tool
│   ├── pmkid.pcapng          # Captured PMKID data
│   └── pmkid.22000           # Hashcat-compatible hash file
├── saved-pmkid/              # Saved PMKID captures
├── instr.txt                 # Detailed instructions
└── README.md                 # This file
```

## 🎯 Attack Workflow

```
1. Interface Setup → 2. Network Scan → 3. PMKID Capture → 4. Hash Conversion → 5. Password Cracking
```

## ⚠️ Important Notes

- **Legal Use Only**: This tool is for educational and authorized penetration testing
- **Monitor Mode**: Disables normal WiFi connection during use
- **Wordlists**: Keep rockyou.txt ready for password cracking
- **Interface Names**: The tool automatically handles interface name changes
- **Root Access**: Always run with sudo for wireless operations

## 🔄 Restore WiFi Connection

After using the tool, restore normal WiFi:

```bash
# Stop monitor mode
sudo airmon-ng stop wlp3s0mon

# Restart network manager
sudo systemctl restart NetworkManager
```

## 📚 Additional Resources

- **Instructions**: See `instr.txt` for detailed command reference
- **Troubleshooting**: Check interface setup in the instructions
- **Wordlists**: Download rockyou.txt for effective password cracking

## ⚖️ Disclaimer

This tool is intended for **educational purposes and authorized penetration testing only**. Users are responsible for ensuring they have proper authorization before testing any network. The authors are not responsible for any misuse of this tool.

---

**Happy Hacking! 🔓**
