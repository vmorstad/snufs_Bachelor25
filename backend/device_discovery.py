import re
import socket
from scapy.all import ARP, Ether, srp
import subprocess

def scan_network(network_range):
    arp = ARP(pdst=network_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=5, verbose=True)[0]
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

def normalize_cpe(cpe_string):
    """Normalize CPE strings to the format expected by the CVE database"""
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
    try:
        # More reliable OS detection with service version detection
        nmap_result = subprocess.check_output([
            "nmap",
            "-sV",                    # Service/version detection
            "-O",                     # OS detection
            "--osscan-limit",         # Limit OS detection to promising targets
            "--max-os-tries", "1",    # Limit OS detection retries
            "-p-",                    # Scan all ports
            "--version-light",        # Light version detection
            ip_address
        ], universal_newlines=True, stderr=subprocess.STDOUT)
        
        # First try to get OS from service detection
        service_os = parse_service_os(nmap_result)
        if service_os:
            return service_os
            
        # Fall back to regular OS detection
        return parse_os_info(nmap_result)
    except subprocess.CalledProcessError as e:
        return f"Error running Nmap on {ip_address}: {e.output if hasattr(e, 'output') else str(e)}"

def parse_service_os(nmap_output):
    """Try to determine OS from service detection results"""
    windows_indicators = [
        "Microsoft Windows",
        "microsoft-ds",
        "netbios-ssn",
        "msrpc"
    ]
    
    linux_indicators = [
        "Linux",
        "Unix",
        "OpenSSH",
        "sshd"
    ]
    
    lines = nmap_output.splitlines()
    windows_count = 0
    linux_count = 0
    
    for line in lines:
        line = line.lower()
        for indicator in windows_indicators:
            if indicator.lower() in line:
                windows_count += 1
        for indicator in linux_indicators:
            if indicator.lower() in line:
                linux_count += 1
    
    if windows_count > linux_count and windows_count > 0:
        return "Microsoft Windows"
    elif linux_count > windows_count and linux_count > 0:
        return "Linux"
    
    return None

def parse_os_info(nmap_output):
    lines = nmap_output.splitlines()
    os_matches = []
    
    for line in lines:
        line = line.strip()
        if "OS details:" in line:
            os_matches.append(line.split(":", 1)[1].strip())
        elif "Running:" in line:
            os_matches.append(line.split(":", 1)[1].strip())
        elif "OS CPE:" in line:
            cpe = line.split(":", 1)[1].strip()
            if cpe.startswith("cpe:/o:") or cpe.startswith("cpe:2.3:o:"):
                normalized_cpe = normalize_cpe(cpe)
                if normalized_cpe and normalized_cpe not in os_matches:
                    os_matches.append(normalized_cpe)
    
    # If we found any OS matches, return them
    if os_matches:
        return " | ".join(os_matches)
    
    # If no matches but we see Windows services
    if any("microsoft" in line.lower() or "windows" in line.lower() for line in lines):
        return "cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*"
    
    if "No exact OS matches" in nmap_output:
        return "No exact OS match"
    return "Unknown OS or Version"

def get_device_name(ip_address):
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        return hostname
    except socket.herror:
        return "Unknown device name"

def scan_ports(ip_address):
    """
    Basic port scanning with service detection
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
