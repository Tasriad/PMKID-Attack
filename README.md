# WiFi Pentesting Tool

A powerful **WiFi penetration testing tool** built using Python. This tool automates various WiFi security tests like **network scanning, handshake capture, WPA2 cracking, WPS attacks, PMKID attacks, and deauthentication attacks**.

## 🚀 Features
- **Monitor Mode Management**: Enables/disables monitor mode on a WiFi adapter.
- **Network Scanning**: Lists available WiFi networks.
- **Handshake Capture**: Captures WPA2 handshakes for password cracking.
- **WPA2 Password Cracking**: Uses wordlists to crack captured handshakes.
- **WPS Attacks**: Exploits WPS vulnerabilities to retrieve WiFi passwords.
- **PMKID Attack**: Captures and cracks PMKID hashes without client interaction.
- **Deauthentication Attack**: Disconnects users from a WiFi network.
- **Custom Password List Generator**: Creates wordlists using `crunch`.

## 📦 Dependencies
Make sure you have the following tools installed before running the script:
- `aircrack-ng`
- `hcxtools`
- `hcxdumptool`
- `reaver`
- `crunch`
- `xterm`

### Install dependencies (Debian-based systems)
```bash
sudo apt-get update && sudo apt-get install xterm aircrack-ng hcxtools hcxdumptool crunch reaver -y
```

## 🛠️ Usage
Run the script with **root** privileges:
```bash
sudo python3 wifi-pentest.py
```

### Available Options:
1. **Networks Attacks** (Requires BSSID and monitor mode)
2. **Scan Networks**
3. **Capture Handshake** (Requires monitor mode)
4. **Crack Handshake** (Uses wordlist)
5. **Create a Custom Password List**

## ⚠️ Disclaimer
This tool is intended for **educational purposes** only. **Do not use it for illegal activities.** The author is not responsible for any misuse.

## 📜 License
This project is licensed under the **MIT License**. Feel free to modify and use it!
