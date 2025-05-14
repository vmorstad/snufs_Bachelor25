import re
import subprocess

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

def extract_most_specific_os(os_string):
    """
    Extract the most specific OS information from Nmap output.
    """
    if 'windows' in os_string.lower():
        # Just extract the version number if present
        match = re.search(r'windows\s*(?:nt\s*)?(\d+(?:\.\d+)?)', os_string, re.IGNORECASE)
        if match:
            return f"Windows {match.group(1)}"
        return "Windows"
    return os_string

def detect_os(ip_address):
    """
    Detect the operating system of a device using Nmap.
    Returns a dict with both raw and normalized OS info.
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
        os_normalized = extract_most_specific_os(os_info)
        return {
            "os": os_info,
            "os_normalized": os_normalized
        }
    except subprocess.CalledProcessError as e:
        print(f"Error detecting OS for {ip_address}: {e}")
        return {"os": "Unknown", "os_normalized": "Unknown"}

def parse_os_info(nmap_output):
    """
    Parse OS information from Nmap output.
    """
    os_lines = [line for line in nmap_output.split('\n') if 'OS details:' in line]
    if not os_lines:
        return "Unknown"
    
    # Extract from OS details
    for line in os_lines:
        if 'OS details:' in line:
            os_match = re.search(r'OS details: ([^,]+)', line)
            if os_match:
                return os_match.group(1)
    
    return "Unknown"
