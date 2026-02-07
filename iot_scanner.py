import scapy.all as scapy
import requests
import shodan
import socket
import sys
from colorama import Fore, Style, init

# Initialize colorama for colored output
init(autoreset=True)

# --- CONFIGURATION ---
# REPLACE THIS WITH YOUR ACTUAL SHODAN API KEY
SHODAN_API_KEY = "9fIXKYdA47bItWd2thfKmtLXfuA0T8x6"

# A basic dictionary of known default credentials for common IoT Vendors
# In a real scenario, this would be a much larger database
DEFAULT_CREDS = {
    "Raspberry Pi": ("pi", "raspberry"),
    "Espressif": ("admin", "admin"),  # Common generic
    "TP-Link": ("admin", "admin"),
    "Hikvision": ("admin", "12345"),
    "Netgear": ("admin", "password"),
    "D-Link": ("admin", ""),
    "Apple": ("N/A", "Apple devices usually secure"),
    "Google": ("N/A", "Cloud managed"),
    "Amazon": ("N/A", "Cloud managed")
}

def get_local_ip_range():
    """
    Automatically detects the local IP and assumes a /24 subnet.
    Example: if local IP is 192.168.1.15, returns 192.168.1.1/24
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't actually connect, just determines the route
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        # Assume standard home class C network
        ip_parts = local_ip.split('.')
        base_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1/24"
        return base_ip
    except Exception as e:
        print(f"{Fore.RED}[!] Could not detect local IP: {e}")
        return None

def scan_network(ip_range):
    """
    Uses Scapy to send ARP requests to the IP range.
    Returns a list of dictionaries containing IP and MAC addresses.
    """
    print(f"{Fore.CYAN}[*] Scanning network range: {ip_range} ...")
    
    # Create ARP request
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    
    # Send packet and receive response (verbose=False hides scapy noise)
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    
    devices = []
    for element in answered_list:
        device = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        devices.append(device)
    
    print(f"{Fore.GREEN}[+] Found {len(devices)} devices.")
    return devices

def get_vendor(mac_address):
    """
    Uses an online API to look up the vendor based on MAC address.
    """
    url = f"https://api.macvendors.com/{mac_address}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.text
        else:
            return "Unknown Vendor"
    except:
        return "Lookup Failed"

def check_shodan_vulns(vendor_name):
    """
    Queries Shodan to see if there are general known exploits for this vendor.
    Note: This checks for the VENDOR, not the specific device IP (since it's local).
    """
    if vendor_name == "Unknown Vendor" or not SHODAN_API_KEY:
        return []

    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        # Search for exploits related to the vendor
        # We limit to 3 results to keep output clean
        results = api.search(f"{vendor_name} vulnerability", limit=3)
        vulns = []
        for result in results['matches']:
            vulns.append(result.get('data', 'No details').strip()[:100] + "...") # Truncate long text
        return vulns
    except shodan.APIError as e:
        return [f"Shodan Error: {e}"]
    except Exception:
        return []

def analyze_devices(devices):
    """
    Iterates through found devices, enriches data, and prints report.
    """
    print(f"\n{Fore.YELLOW}{'='*60}")
    print(f"{Fore.YELLOW}IOT VULNERABILITY REPORT")
    print(f"{Fore.YELLOW}{'='*60}\n")

    for device in devices:
        ip = device['ip']
        mac = device['mac']
        
        # 1. Identify Vendor
        vendor = get_vendor(mac)
        
        print(f"{Fore.BLUE}[DEVICE] IP: {ip} | MAC: {mac}")
        print(f"         Vendor: {Fore.WHITE}{vendor}")

        # 2. Check for Default Passwords (The Logic from your prompt)
        # We match partial strings (e.g. "Espressif Inc" matches "Espressif")
        default_found = False
        for key, creds in DEFAULT_CREDS.items():
            if key.lower() in vendor.lower():
                print(f"         {Fore.RED}[!] RISK: Possible Default Credentials found!")
                print(f"         {Fore.RED}    User: {creds[0]} / Pass: {creds[1]}")
                default_found = True
                break
        
        if not default_found:
            print(f"         {Fore.GREEN}[+] No common default credentials database match.")

        # 3. Check Shodan for Vendor Intel
        # (Only do this if we have a valid vendor name)
        if vendor != "Unknown Vendor":
            print(f"         {Fore.CYAN}[?] Checking Shodan for vendor intel...")
            vulns = check_shodan_vulns(vendor)
            if vulns:
                print(f"             {Fore.MAGENTA}Recent related chatter/vulns:")
                for v in vulns:
                    print(f"             - {v}")
            else:
                print(f"             No immediate vendor alerts found via API.")
        
        print(f"{Fore.WHITE}{'-'*60}")

def main():
    # 1. Get Target
    target_ip = get_local_ip_range()
    if not target_ip:
        sys.exit(1)

    # 2. Scan
    devices_list = scan_network(target_ip)
    
    if not devices_list:
        print("No devices found. Try running as sudo/administrator.")
        sys.exit()

    # 3. Analyze
    analyze_devices(devices_list)

if __name__ == "__main__":
    main()