import re
from scapy.all import ARP, Ether, srp
import subprocess

def scan_network(network_range):
    """
    Scan the network for active devices using ARP requests.
    Args: network_range (str). The network range to scan (e.g., '192.168.1.0/24')
    Returns a list of dictionaries containing IP and MAC addresses of discovered devices.
    """
    arp = ARP(pdst=network_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=5, verbose=True)[0]
    devices = []
    for sent, received in result:
        devices.append({
            'ip': received.psrc,
            'mac': received.hwsrc
        })
    return devices

def normalize_cpe(cpe_string):
    """
    Normalize CPE strings to the format expected by the CVE database.
    Args cpe_string (str). The CPE string to normalize.
    Returns str or None. Normalized CPE string or None if invalid.
    """
    if not cpe_string:
        return None
        
    # If it's already in CPE 2.3 format, return as is
    if cpe_string.startswith("cpe:2.3:"):
        return cpe_string
        
    # Convert old format to 2.3
    if cpe_string.startswith("cpe:/"):
        parts = cpe_string.split(":")
        if len(parts) < 3:
            return None
            
        vendor_product = parts[2].split("/")
        if len(vendor_product) != 2:
            return None
            
        vendor = vendor_product[0]
        product = vendor_product[1]
        
        # Construct CPE 2.3 format
        return f"cpe:2.3:o:{vendor}:{product}:*:*:*:*:*:*:*:*"
    
    return None

def detect_os(ip_address):
    """
    Detect the operating system of a device using Nmap.
    """
    try:
        nmap_result = subprocess.check_output([
            "nmap",
            "-sV",                    # Service/version detection
            "-O",                     # OS detection
            "--osscan-limit",         # Limit OS detection to promising targets
            ip_address
        ], universal_newlines=True)
        
        # Parse OS information from Nmap output
        os_info = parse_os_info(nmap_result)
        return os_info
    except subprocess.CalledProcessError as e:
        print(f"Error detecting OS for {ip_address}: {e}")
        return "Unknown"

def parse_os_info(nmap_output):
    """
    Parse OS information from Nmap output.
    """
    os_lines = [line for line in nmap_output.split('\n') if 'OS details:' in line or 'OS CPE:' in line]
    if not os_lines:
        return "Unknown"
    
    # Try to extract OS name from CPE first
    for line in os_lines:
        if 'OS CPE:' in line:
            cpe_match = re.search(r'cpe:/[^:]+:([^:]+):', line)
            if cpe_match:
                os_name = cpe_match.group(1).replace('_', ' ').title()
                return os_name
    
    # If no CPE, try to extract from OS details
    for line in os_lines:
        if 'OS details:' in line:
            os_match = re.search(r'OS details: ([^,]+)', line)
            if os_match:
                return os_match.group(1)
    
    return "Unknown"

def get_device_name(ip_address):
    """
    Get the device name using multiple methods (DNS, Nmap, NetBIOS).
    """
    try:
        # Try DNS lookup first
        try:
            import socket
            hostname = socket.gethostbyaddr(ip_address)[0]
            if hostname and not re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname):
                return hostname
        except (socket.herror, socket.gaierror):
            pass

        # Try Nmap if DNS fails
        nmap_result = subprocess.run([
            "nmap",
            "-sn",  # Ping scan only
            "-n",   # No DNS resolution
            ip_address
        ], capture_output=True, text=True)
        
        if nmap_result.returncode == 0:
            # Look for hostname in Nmap output
            hostname_match = re.search(r'Nmap scan report for ([^\n]+)', nmap_result.stdout)
            if hostname_match:
                hostname = hostname_match.group(1)
                # If hostname is an IP, return None
                if not re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname):
                    return hostname

        # Try NetBIOS name if available
        try:
            nbtscan_result = subprocess.run([
                "nbtscan",
                ip_address
            ], capture_output=True, text=True)
            
            if nbtscan_result.returncode == 0:
                # Parse NetBIOS name from output
                for line in nbtscan_result.stdout.splitlines():
                    if ip_address in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            name = parts[1]
                            if name and not re.match(r'^\d+\.\d+\.\d+\.\d+$', name):
                                return name
        except (subprocess.SubprocessError, FileNotFoundError):
            pass

        return None
    except Exception as e:
        print(f"Error getting device name for {ip_address}: {e}")
        return None

def scan_ports(ip_address):
    """
    Basic port scanning with service detection using Nmap.
    """
    try:
        nmap_output = subprocess.check_output([
            "nmap",
            "-sV",                    # Version detection
            "-sS",                    # SYN scan
            ip_address
        ], universal_newlines=True)
        
        open_ports = []
        service_info = False
        
        for line in nmap_output.splitlines():
            line = line.strip()
            if "/tcp" in line and "open" in line:
                open_ports.append(line.strip())
                service_info = True
            # Include additional service information
            elif service_info and line and not line.startswith("MAC") and not line.startswith("Nmap"):
                if len(open_ports) > 0:
                    open_ports[-1] = f"{open_ports[-1]} ({line.strip()})"
                service_info = False
                
        return open_ports
    except subprocess.CalledProcessError as e:
        return [f"Error scanning ports on {ip_address}: {e}"]

if __name__ == "__main__":
    # For standalone testing
    network_range = "192.168.0.0/24"
    print("Scanning network for devices...")
    devices = scan_network(network_range)
    if devices:
        print("\nDiscovered devices:")
        for device in devices:
            print(f"IP: {device['ip']}\tMAC: {device['mac']}")
        print("\nRunning OS and Port detection on discovered devices:")
        for device in devices:
            ip = device['ip']
            print(f"\nResults for {ip}:")
            print("OS Info:", detect_os(ip))
            print("Port Scan:", scan_ports(ip))
    else:
        print("No devices discovered. Check your network settings, firewall, or interface.")
    print("Scan complete.")
